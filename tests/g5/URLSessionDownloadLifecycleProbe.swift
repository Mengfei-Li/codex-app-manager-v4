import Foundation

private enum ProbeError: LocalizedError {
    case invalidArguments
    case timeout
    case missingPersistedDownload

    var errorDescription: String? {
        switch self {
        case .invalidArguments:
            return "usage: probe <source-url> <destination-path>"
        case .timeout:
            return "download probe timed out"
        case .missingPersistedDownload:
            return "download completed without a persisted destination"
        }
    }
}

private final class DownloadProbe: NSObject, URLSessionDownloadDelegate {
    private let destination: URL
    private let completion = DispatchSemaphore(value: 0)
    private var persistedDownloadURL: URL?
    private var responseFailure: Error?
    private var result: Result<URL, Error>?
    private var session: URLSession!

    init(destination: URL) {
        self.destination = destination
    }

    func download(from source: URL) throws -> URL {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 60
        session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        session.downloadTask(with: source).resume()
        guard completion.wait(timeout: .now() + 60) == .success else {
            session.invalidateAndCancel()
            throw ProbeError.timeout
        }
        session.finishTasksAndInvalidate()
        return try result!.get()
    }

    func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didFinishDownloadingTo location: URL
    ) {
        if let http = downloadTask.response as? HTTPURLResponse,
           !(200...299).contains(http.statusCode) {
            responseFailure = ProbeError.missingPersistedDownload
            return
        }
        do {
            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.moveItem(at: location, to: destination)
            persistedDownloadURL = destination
        } catch {
            responseFailure = error
            persistedDownloadURL = nil
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: Error?
    ) {
        if let error {
            result = .failure(error)
        } else if let responseFailure {
            result = .failure(responseFailure)
        } else if let persisted = persistedDownloadURL,
                  persisted.standardizedFileURL == destination.standardizedFileURL,
                  FileManager.default.fileExists(atPath: persisted.path) {
            result = .success(destination)
        } else {
            result = .failure(ProbeError.missingPersistedDownload)
        }
        completion.signal()
    }
}

guard CommandLine.arguments.count == 3,
      let source = URL(string: CommandLine.arguments[1]) else {
    fputs("\(ProbeError.invalidArguments.localizedDescription)\n", stderr)
    exit(2)
}

let destination = URL(fileURLWithPath: CommandLine.arguments[2])
do {
    let persisted = try DownloadProbe(destination: destination).download(from: source)
    print(persisted.path)
} catch {
    fputs("\(error.localizedDescription)\n", stderr)
    exit(1)
}
