using System.ComponentModel;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace TotalVirusCheck
{
    internal class Program
    {
        static string? filePath = "";
        static string? apikey = "";
        private static HttpClient httpClient = new HttpClient();
        static async Task Main(string[] args)
        {

            // Check
            if (args.Length != 2)
            {
                Console.WriteLine("File path: ");
                filePath = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(filePath))
                {
                    Console.WriteLine("File path is required.");
                    Console.ReadKey();
                    return;
                }

                Console.WriteLine("API key (or the path to the file containing the API key): ");

                apikey = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(apikey))
                {
                    Console.WriteLine("API key is required.");
                    Console.ReadKey();
                    return;
                }
                

            }
            else
            {
                filePath = args[0];
                apikey = args[1];
            }
            
            
            if (!File.Exists(filePath))
            {
                if (!File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filePath)))
                {
                    Console.WriteLine("Incorrect file path.");
                    Console.ReadKey();
                    return;
                }
                filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filePath);
            }

            try
            {
                if (!File.Exists(apikey))
                {
                    if (File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, apikey)))
                    {
                        apikey = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, apikey)).Trim();
                    }
                }
                else if (File.Exists(apikey))
                {
                    apikey = File.ReadAllText(apikey).Trim();
                }
            }
            catch
            {
                Console.WriteLine("No access to API key file");
                Console.ReadKey();
                return;
            }

            try
            {
                using (FileStream fs = File.OpenRead(filePath))
                {

                }
            }
            catch
            {
                Console.WriteLine("No access to file.");
                Console.ReadKey();
                return;
            }

            //Send

            if(!VirusTotalClient(apikey))
            {
                Console.WriteLine("Internet Error");
                Console.ReadKey();
                return;
            }

            try
            {
                string hash = CalculateFileHash(filePath);

                var checkResult = await CheckHashAsync(hash);
                if (checkResult.Exist)
                {
                    Present(ParseResults(checkResult.Data!), true);
                    Console.ReadKey();
                    return;
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("CheckHash Error");
                Console.WriteLine(ex.Message);
                Console.ReadKey();
                return;
            }

            try
            {
                var uploadResult = await UploadFileAsync(filePath);
                if (!uploadResult.IsCompleted)
                {
                    Console.WriteLine("Scan error");
                    Console.ReadKey();
                    return;
                    // Może trzeba dodać sprawdzenie ponowne id. czy to ma sens?
                }

                Present(ParseResults(uploadResult.Data!), false);
                Console.ReadKey();
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine("UploadFile Error");
                Console.WriteLine(ex.Message);
                Console.ReadKey();
                return;
            }

        }

        public static void Present(ScanSummary summary, bool noted)
        {
            Console.WriteLine("\n═══════════════════════════════════════════════════════");
            Console.WriteLine("VIRUSTOTAL SCAN RESULTS");
            Console.WriteLine("═══════════════════════════════════════════════════════\n");

            Console.WriteLine($"Noted:           {noted}");
            Console.WriteLine($"Status:          {(summary.IsMalicious ? "MALICIOUS" : "CLEAN")}");
            Console.WriteLine($"Malicious:       {summary.MaliciousCount}");
            Console.WriteLine($"Suspicious:      {summary.SuspiciousCount}");
            Console.WriteLine($"Total detections:{summary.MaliciousCount + summary.SuspiciousCount}");

            if (summary.Detections.Any())
            {
                Console.WriteLine("\nDetections:");
                Console.WriteLine("───────────────────────────────────────────────────────");

                int count = 0;
                foreach (var det in summary.Detections)
                {
                    count++;
                    Console.WriteLine($"{count}. [{det.Category.ToUpper()}] {det.Engine}: {det.Result}");
                }


            }

            Console.WriteLine("═══════════════════════════════════════════════════════");
        }

        public static async Task<CheckResult> CheckHashAsync(string hash)
        {


            var response = await httpClient.GetAsync(
                 $"https://www.virustotal.com/api/v3/files/{hash}"
                 );

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return new CheckResult { Exist = false };
            }

            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return new CheckResult
            {
                Exist = true,
                Data = json
            };

        }

        public static async Task<UploadResult> UploadFileAsync(string filePath)
        {
            using var form = new MultipartFormDataContent();
            using var fileStream = File.OpenRead(filePath);
            using var fileContent = new StreamContent(fileStream);

            form.Add(fileContent, "file", Path.GetFileName(filePath));

            var response = await httpClient.PostAsync(
                "https://www.virustotal.com/api/v3/files",
                form
            );

            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return ParseUploadResponse(json);

        }

        public static bool VirusTotalClient(string apikey)
        {
            try
            {
                //httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("x-apikey", apikey);
                httpClient.Timeout = TimeSpan.FromMinutes(5);
                httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("VirusTotalCheck/1.0");
                return true;
            }
            catch { return false; }
        }

        public static ScanSummary ParseResults(string json)
        {
            var summary = new ScanSummary();

            using var doc = JsonDocument.Parse(json);
            var data = doc.RootElement.GetProperty("data");
            var attrs = data.GetProperty("attributes");


            JsonElement stats;
            if (attrs.TryGetProperty("stats", out stats))
            {
                summary.MaliciousCount = stats.GetProperty("malicious").GetInt32();
                summary.SuspiciousCount = stats.GetProperty("suspicious").GetInt32();
            }
            else if (attrs.TryGetProperty("last_analysis_stats", out stats))
            {
                summary.MaliciousCount = stats.GetProperty("malicious").GetInt32();
                summary.SuspiciousCount = stats.GetProperty("suspicious").GetInt32();
            }

            summary.IsMalicious = summary.MaliciousCount > 0;

            JsonElement results;
            if (attrs.TryGetProperty("results", out results) ||
                attrs.TryGetProperty("last_analysis_results", out results))
            {
                foreach (var engine in results.EnumerateObject())
                {
                    var scan = engine.Value;
                    var category = scan.GetProperty("category").GetString();

                    if (category == "malicious" || category == "suspicious")
                    {
                        summary.Detections.Add(new Detection
                        {
                            Engine = engine.Name,
                            Result = scan.GetProperty("result").GetString()!,
                            Category = category
                        });
                    }
                }
            }

            return summary;
        }


        public static string CalculateFileHash(string filePath)
        {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hashBytes = sha256.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }

        public static UploadResult ParseUploadResponse(string json)
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var analysisId = root
                .GetProperty("data")
                .GetProperty("id")
                .GetString();

            var status = root
                .GetProperty("data")
                .GetProperty("attributes")
                .GetProperty("status")
                .GetString();

            return new UploadResult
            {
                AnalysisId = analysisId!,
                IsCompleted = status == "completed",
                Data = status == "completed" ? json : null
            };
        }


        public class CheckResult
        {
            public bool Exist { get; set; }
            public string? Data { get; set; }
        }

        public class UploadResult
        {
            public required string AnalysisId { get; set; }
            public required bool IsCompleted { get; set; }
            public string? Data { get; set; }
        }

        public class ScanSummary
        {
            public bool IsMalicious { get; set; }
            public int MaliciousCount { get; set; }
            public int SuspiciousCount { get; set; }
            public int TotalEngines { get; set; }
            public List<Detection> Detections { get; set; } = new();
        }

        public class Detection
        {
            public required string Engine { get; set; }
            public required string Result { get; set; }
            public required string Category { get; set; }
        }

    }

}
