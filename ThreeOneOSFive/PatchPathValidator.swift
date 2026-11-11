import Foundation

/// 移植自 3105 的 PatchProjectModels.PatchPathValidator（只保留 bundle id 校验）。
enum PatchPathValidator {
    static func canonicalBundleIdentifier(_ rawValue: String) -> String? {
        let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              value.utf8.count <= 255,
              UUID(uuidString: value) == nil,
              !value.contains("/"),
              !value.contains("\\"),
              !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { return nil }

        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count >= 2 else { return nil }

        for component in components {
            guard !component.isEmpty,
                  component.unicodeScalars.allSatisfy({ scalar in
                      let v = scalar.value
                      return (48...57).contains(v) || (65...90).contains(v)
                          || (97...122).contains(v) || v == 45
                  }),
                  component.first != "-",
                  component.last != "-"
            else { return nil }
        }
        return value
    }
}
