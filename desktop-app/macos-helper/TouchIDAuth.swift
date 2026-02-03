import Foundation
import LocalAuthentication

let context = LAContext()
var error: NSError?

// Check if any authentication method is available (Touch ID or device passcode)
guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
    fputs("ERROR: No authentication method available: \(error?.localizedDescription ?? "unknown")\n", stderr)
    exit(2)
}

// Use deviceOwnerAuthentication: shows Touch ID first, with "Use Password..." fallback
let semaphore = DispatchSemaphore(value: 0)
var authSuccess = false

context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock LLM Secrets vault") { success, authError in
    authSuccess = success
    if !success {
        fputs("ERROR: Authentication failed: \(authError?.localizedDescription ?? "unknown")\n", stderr)
    }
    semaphore.signal()
}

semaphore.wait()
exit(authSuccess ? 0 : 1)
