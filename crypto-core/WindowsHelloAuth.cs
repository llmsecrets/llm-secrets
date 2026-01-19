using System;
using System.Threading.Tasks;
using Windows.Security.Credentials.UI;
using System.Runtime.InteropServices.WindowsRuntime;

namespace EnvCrypto
{
    class WindowsHelloAuth
    {
        static int Main(string[] args)
        {
            return MainAsync(args).GetAwaiter().GetResult();
        }

        static async Task<int> MainAsync(string[] args)
        {
            try
            {
                string message = "EnvCrypto - Authenticate to access encrypted secrets";

                // Allow custom message from command line
                if (args.Length > 0)
                {
                    message = string.Join(" ", args);
                }

                Console.WriteLine("Checking Windows Hello availability...");

                // Check if Windows Hello is available
                var availability = await UserConsentVerifier.CheckAvailabilityAsync().AsTask();

                if (availability != UserConsentVerifierAvailability.Available)
                {
                    Console.WriteLine("ERROR: Windows Hello is not available.");
                    Console.WriteLine("Status: " + availability.ToString());
                    Console.WriteLine("");
                    Console.WriteLine("Possible reasons:");
                    Console.WriteLine("- Windows Hello is not set up on this device");
                    Console.WriteLine("- No biometric hardware or PIN configured");
                    Console.WriteLine("- Device does not support Windows Hello");
                    return 2; // Exit code 2: Not available
                }

                Console.WriteLine("Windows Hello is available.");
                Console.WriteLine("Requesting authentication...");
                Console.WriteLine("");

                // Request Windows Hello authentication
                var result = await UserConsentVerifier.RequestVerificationAsync(message).AsTask();

                if (result == UserConsentVerificationResult.Verified)
                {
                    Console.WriteLine("SUCCESS: Authentication verified");
                    return 0; // Exit code 0: Success
                }
                else
                {
                    Console.WriteLine("FAILED: Authentication failed");
                    Console.WriteLine("Result: " + result.ToString());
                    return 1; // Exit code 1: Failed or cancelled
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: " + ex.Message);
                Console.WriteLine(ex.StackTrace);
                return 3; // Exit code 3: Exception occurred
            }
        }
    }
}
