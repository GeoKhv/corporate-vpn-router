import Foundation
var stale = false
let url = try URL(resolvingBookmarkData: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])),
                  options: [.withoutUI, .withoutMounting], relativeTo: nil, bookmarkDataIsStale: &stale)
print(url.path)
