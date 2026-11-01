import Foundation
import GRDB

enum Database {
    static let sharedWriter = makeShared()

    private static func makeShared() -> any DatabaseWriter {
        let fileManager = FileManager.default
        // 先读 isSharedDirectoryAvailable（不会强制解包），拿不到容器时不要再碰 sharedDirectory
        let groupDirectory: URL? = FilePath.isSharedDirectoryAvailable ? FilePath.sharedDirectory : nil

        // 1) 正常路径：App Group 容器
        if let writer = open(in: groupDirectory, label: "app-group") {
            return writer
        }

        // 2) 容器里已有打不开的旧库（schema 冲突 / 权限 / 残留锁）：备份后重建
        if let groupDirectory {
            let databaseURL = groupDirectory.appendingPathComponent("settings.db")
            if fileManager.fileExists(atPath: databaseURL.path) {
                let backupURL = databaseURL.appendingPathExtension(
                    "broken-\(Int(Date().timeIntervalSince1970))"
                )
                do {
                    try fileManager.moveItem(at: databaseURL, to: backupURL)
                    NSLog("Database: moved unreadable settings.db to %@", backupURL.lastPathComponent)
                } catch {
                    NSLog("Database: cannot move old settings.db — %@", error.localizedDescription)
                }
                if let writer = open(in: groupDirectory, label: "app-group-recreated") {
                    return writer
                }
            }
        }

        // 3) 沙盒 Documents 兜底：主程序先能启动（扩展读不到库时 VPN 配置同步会退化）
        let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
        if let writer = open(in: documentsDirectory, label: "documents") {
            return writer
        }

        // 4) 内存库兜底，保证进程不崩
        if let memoryWriter = try? DatabaseQueue() {
            NSLog("Database: falling back to in-memory store")
            return memoryWriter
        }

        fatalError("Database: no writable location for settings.db")
    }

    private static func open(in directory: URL?, label: String) -> (any DatabaseWriter)? {
        guard let directory else {
            NSLog("Database: %@ directory unavailable", label)
            return nil
        }

        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let database = try DatabasePool(
                path: directory.appendingPathComponent("settings.db").relativePath
            )
            var migrator = DatabaseMigrator().disablingDeferredForeignKeyChecks()
            migrator.registerMigration("initialize") { db in
                try db.create(table: "profiles") { t in
                    t.autoIncrementedPrimaryKey("id")
                    t.column("name", .text).notNull()
                    t.column("order", .integer).notNull()
                    t.column("type", .integer).notNull().defaults(to: ProfileType.local.rawValue)
                    t.column("path", .text).notNull()
                    t.column("remoteURL", .text)
                    t.column("autoUpdate", .boolean).notNull().defaults(to: false)
                    t.column("lastUpdated", .datetime)
                }
                try db.create(table: "preferences") { t in
                    t.primaryKey("name", .text, onConflict: .replace).notNull()
                    t.column("data", .blob)
                }
            }
            migrator.registerMigration("add_auto_update_interval") { db in
                try db.alter(table: "profiles") { t in
                    t.add(column: "autoUpdateInterval", .integer).notNull().defaults(to: 0)
                }
            }
            try migrator.migrate(database)
            NSLog("Database: opened (%@) at %@", label, directory.path)
            return database
        } catch {
            NSLog("Database: %@ open failed — %@", label, error.localizedDescription)
            return nil
        }
    }
}
