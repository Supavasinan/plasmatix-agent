package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
)

type EntityType string

const (
	EntityDepartments EntityType = "departments"
	EntityEmployees   EntityType = "employees"
	EntityDevices     EntityType = "devices"
	EntityAttendance  EntityType = "attendance"
)

type BatchCursor struct {
	AfterID int64 `json:"afterId"`
}

type SourceFingerprint struct {
	Product          string `json:"product"`
	DatabaseName     string `json:"databaseName"`
	ServerVersion    string `json:"serverVersion"`
	DatabaseIdentity string `json:"databaseIdentity"`
	SHA256           string `json:"sha256"`
}

type SourceInventory struct {
	Counts map[EntityType]int64 `json:"counts"`
}

type SourceBatch struct {
	Entity     EntityType       `json:"entity"`
	Rows       []map[string]any `json:"rows"`
	NextCursor BatchCursor      `json:"nextCursor"`
}

type MigrationSource interface {
	Preflight(context.Context) (SourceFingerprint, error)
	Inventory(context.Context) (SourceInventory, error)
	ReadBatch(context.Context, EntityType, BatchCursor, int) (SourceBatch, error)
}

type MigrationQueryer interface {
	QueryRows(
		context.Context,
		string,
		string,
		...any,
	) ([]map[string]any, error)
}

type MigrationReadOnlyBackend interface {
	WithReadOnly(context.Context, func(MigrationQueryer) error) error
}

const (
	migrationQueryPreflight = "zkbiotime.preflight.v1"
	migrationQueryInventory = "zkbiotime.inventory.v1"
)

var migrationBatchQueries = map[EntityType]struct {
	id  string
	sql string
}{
	EntityDepartments: {
		id: "zkbiotime.departments.v1",
		sql: `SELECT id, dept_code, dept_name, parent_dept_id
			FROM personnel_department WHERE id > $1 ORDER BY id LIMIT $2`,
	},
	EntityEmployees: {
		id: "zkbiotime.employees.v1",
		sql: `SELECT id, emp_code, first_name, last_name, department_id,
			card_no, hire_date, enable_att, deleted
			FROM personnel_employee WHERE id > $1 ORDER BY id LIMIT $2`,
	},
	EntityDevices: {
		id: "zkbiotime.devices.v1",
		sql: `SELECT id, sn, alias, ip_address, terminal_name
			FROM iclock_terminal WHERE id > $1 ORDER BY id LIMIT $2`,
	},
	EntityAttendance: {
		id: "zkbiotime.attendance.v1",
		sql: `SELECT id, emp_code, punch_time, punch_state, verify_type,
			terminal_sn, work_code
			FROM iclock_transaction WHERE id > $1 ORDER BY id LIMIT $2`,
	},
}

const migrationPreflightSQL = `SELECT
	current_database() AS database_name,
	current_setting('server_version') AS server_version,
	to_regclass('public.personnel_employee') IS NOT NULL AS employees_table,
	to_regclass('public.iclock_transaction') IS NOT NULL AS attendance_table`

const migrationInventorySQL = `SELECT
	(SELECT count(*) FROM personnel_department) AS departments,
	(SELECT count(*) FROM personnel_employee) AS employees,
	(SELECT count(*) FROM iclock_terminal) AS devices,
	(SELECT count(*) FROM iclock_transaction) AS attendance`

var allowedMigrationSQL = func() map[string]string {
	queries := map[string]string{
		migrationQueryPreflight: migrationPreflightSQL,
		migrationQueryInventory: migrationInventorySQL,
	}
	for _, query := range migrationBatchQueries {
		queries[query.id] = query.sql
	}
	return queries
}()

type ZKBioTimeMigrationSource struct {
	backend MigrationReadOnlyBackend
	dsn     string
	secret  string
}

func NewZKBioTimeMigrationSource(
	backend MigrationReadOnlyBackend,
	dsn string,
) *ZKBioTimeMigrationSource {
	secret := ""
	if parsed, err := url.Parse(dsn); err == nil && parsed.User != nil {
		secret, _ = parsed.User.Password()
	}
	return &ZKBioTimeMigrationSource{
		backend: backend,
		dsn:     dsn,
		secret:  secret,
	}
}

func NewZKBioTimePostgresSource(dsn string) *ZKBioTimeMigrationSource {
	return NewZKBioTimeMigrationSource(&PGXMigrationBackend{dsn: dsn}, dsn)
}

type PGXMigrationBackend struct {
	dsn string
}

func (backend *PGXMigrationBackend) WithReadOnly(
	ctx context.Context,
	run func(MigrationQueryer) error,
) error {
	connection, err := pgx.Connect(ctx, backend.dsn)
	if err != nil {
		return err
	}
	defer connection.Close(context.Background())

	transaction, err := connection.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return err
	}
	defer transaction.Rollback(context.Background())
	if _, err := transaction.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
		return fmt.Errorf("enforce read-only transaction: %w", err)
	}
	return run(&pgxMigrationQueryer{transaction: transaction})
}

type pgxMigrationQueryer struct {
	transaction pgx.Tx
}

func (queryer *pgxMigrationQueryer) QueryRows(
	ctx context.Context,
	queryID string,
	query string,
	arguments ...any,
) ([]map[string]any, error) {
	allowed, ok := allowedMigrationSQL[queryID]
	if !ok || strings.TrimSpace(allowed) != strings.TrimSpace(query) {
		return nil, fmt.Errorf("migration query %q is not allowlisted", queryID)
	}

	rows, err := queryer.transaction.Query(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	result := make([]map[string]any, 0)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		row := make(map[string]any, len(values))
		for index, value := range values {
			row[string(fields[index].Name)] = value
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *ZKBioTimeMigrationSource) Preflight(
	ctx context.Context,
) (SourceFingerprint, error) {
	var result SourceFingerprint
	err := s.backend.WithReadOnly(ctx, func(queryer MigrationQueryer) error {
		rows, err := queryer.QueryRows(
			ctx,
			migrationQueryPreflight,
			migrationPreflightSQL,
		)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return fmt.Errorf("preflight returned %d rows", len(rows))
		}
		row := rows[0]
		employeesOK, _ := row["employees_table"].(bool)
		attendanceOK, _ := row["attendance_table"].(bool)
		if !employeesOK || !attendanceOK {
			return fmt.Errorf("unsupported ZKBioTime schema")
		}
		databaseName := fmt.Sprint(row["database_name"])
		serverVersion := fmt.Sprint(row["server_version"])
		hash, err := HashMigrationRecord(map[string]any{
			"product":        "zkbiotime",
			"database_name":  databaseName,
			"server_version": serverVersion,
		})
		if err != nil {
			return err
		}
		result = SourceFingerprint{
			Product:          "zkbiotime",
			DatabaseName:     databaseName,
			ServerVersion:    serverVersion,
			DatabaseIdentity: "postgresql:" + databaseName,
			SHA256:           hash,
		}
		return nil
	})
	if err != nil {
		return SourceFingerprint{}, s.redactError(err)
	}
	return result, nil
}

func (s *ZKBioTimeMigrationSource) Inventory(
	ctx context.Context,
) (SourceInventory, error) {
	inventory := SourceInventory{Counts: make(map[EntityType]int64)}
	err := s.backend.WithReadOnly(ctx, func(queryer MigrationQueryer) error {
		rows, err := queryer.QueryRows(
			ctx,
			migrationQueryInventory,
			migrationInventorySQL,
		)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return fmt.Errorf("inventory returned %d rows", len(rows))
		}
		for _, entity := range []EntityType{
			EntityDepartments,
			EntityEmployees,
			EntityDevices,
			EntityAttendance,
		} {
			inventory.Counts[entity] = int64Value(rows[0][string(entity)])
		}
		return nil
	})
	if err != nil {
		return SourceInventory{}, s.redactError(err)
	}
	return inventory, nil
}

func (s *ZKBioTimeMigrationSource) ReadBatch(
	ctx context.Context,
	entity EntityType,
	cursor BatchCursor,
	limit int,
) (SourceBatch, error) {
	query, ok := migrationBatchQueries[entity]
	if !ok {
		return SourceBatch{}, fmt.Errorf("unsupported migration entity %q", entity)
	}
	if limit < 1 || limit > 5000 {
		return SourceBatch{}, fmt.Errorf("batch limit must be between 1 and 5000")
	}

	batch := SourceBatch{Entity: entity, NextCursor: cursor}
	err := s.backend.WithReadOnly(ctx, func(queryer MigrationQueryer) error {
		rows, err := queryer.QueryRows(ctx, query.id, query.sql, cursor.AfterID, limit)
		if err != nil {
			return err
		}
		batch.Rows = rows
		for _, row := range rows {
			if id := int64Value(row["id"]); id > batch.NextCursor.AfterID {
				batch.NextCursor.AfterID = id
			}
		}
		return nil
	})
	if err != nil {
		return SourceBatch{}, s.redactError(err)
	}
	return batch, nil
}

func (s *ZKBioTimeMigrationSource) redactError(err error) error {
	message := err.Error()
	if s.secret != "" {
		message = strings.ReplaceAll(message, s.secret, "[REDACTED]")
	}
	if s.dsn != "" {
		message = strings.ReplaceAll(message, s.dsn, "[REDACTED_DSN]")
	}
	return fmt.Errorf("ZKBioTime migration source: %s", message)
}

func int64Value(value any) int64 {
	switch number := value.(type) {
	case int:
		return int64(number)
	case int32:
		return int64(number)
	case int64:
		return number
	case float64:
		return int64(number)
	default:
		return 0
	}
}
