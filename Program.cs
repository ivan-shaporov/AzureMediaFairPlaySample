using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;
using Microsoft.WindowsAzure.MediaServices.Client.FairPlay;
using Newtonsoft.Json;

namespace CreateFairPlayProtectedAsset
{
    class Program
    {
        private static readonly string pfxPath = @"<path to the .pfx certificate file>";
        private static readonly string pfxPassword = "<password for the .pfx certificate file>";
        private static readonly byte[] askBytes = HexToBytes("<ASk bytes in hex>");

        private static readonly string derPath = @"<path to public certificate file>";

        private static readonly Uri _wamsEndpoint = new Uri("https://<WAMS endpoint host>.cloudapp.net/");
        private static readonly string _wamsAccount = "<your WAMS account name>";
        private static readonly string _wamsAccountKey = "<your WAMS account key>";
        private static readonly string _wamsAcsBaseAddress = "https://<WAMS ACS host>.accesscontrol.windows.net/";
        private static readonly string _wamsAcsScope = "<WAMS ACS scope>";

        private static readonly string _assetFolder = "<path to the folder with your asset files>";

        private static CloudMediaContext _mediaContext;
        private static readonly string _kidPrefix = "nb:kid:UUID:";

        static void Main(string[] args)
        {
            VerifyCerts();
        
            var credentials = new MediaServicesCredentials(_wamsAccount, _wamsAccountKey)
            {
                AcsBaseAddress = _wamsAcsBaseAddress,
                Scope = _wamsAcsScope
            };

            _mediaContext = new CloudMediaContext(_wamsEndpoint, credentials);

            IAsset asset = CreateAsset();

            IContentKey key = CreateKeyWithPolicy(asset);

            IAssetDeliveryPolicy assetDeliveryPolicy = CreateAssetDeliveryPolicy(asset, key);

            asset.DeliveryPolicies.Add(assetDeliveryPolicy);

            Console.WriteLine("Asset Delivery Policy Added");

            ILocator streamingLocator = CreateLocator(asset);

            IStreamingEndpoint origin = GetOrigin(recreate: false);

            Uri uri = GetManifestUrl(origin, asset, streamingLocator);

            string keyDeliveryUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.FairPlay).ToString();

            Console.WriteLine("ism: {0}\nkey delivery: {1}", uri, keyDeliveryUrl);

            Console.ReadKey();
        }

        private static void VerifyCerts()
        {
            var pfxCert = new X509Certificate2(pfxPath, pfxPassword);

            var derCert = new X509Certificate2(derPath);

            if(derCert.Thumbprint != pfxCert.Thumbprint)
            {
                throw new Exception("Certificates thumbprint mismatch");
            }

            var publicKey = derCert.PublicKey.Key;
            var keyFormatter = new System.Security.Cryptography.RSAOAEPKeyExchangeFormatter(publicKey);

            byte[] clear = Guid.NewGuid().ToByteArray();
            var encrypted = keyFormatter.CreateKeyExchange(clear);

            var serverRsaKey = (System.Security.Cryptography.RSACryptoServiceProvider)pfxCert.PrivateKey;
            var keyDeformatter = new System.Security.Cryptography.RSAOAEPKeyExchangeDeformatter(serverRsaKey);

            byte[] decrypted = keyDeformatter.DecryptKeyExchange(encrypted);

            bool ok = clear.SequenceEqual(decrypted);

            if (!ok)
            {
                throw new Exception("Certificates mismatch");
            }
        }

        private static Uri GetManifestUrl(IStreamingEndpoint origin, IAsset asset, ILocator streamingLocator)
        {
            string manifestFormat = "(format=m3u8-aapl)";

            string url = string.Format("{0}{1}.ism/manifest{2}", streamingLocator.Path, asset.Name, manifestFormat);
            Uri uri = new Uri(url);

            var builder = new UriBuilder(uri);
            builder.Scheme = "https";
            builder.Host = origin.HostName;
            builder.Port = -1;
            uri = builder.Uri;
            return uri;
        }

        private static ILocator CreateLocator(IAsset asset)
        {
            ILocator streamingLocator = _mediaContext
                            .Locators
                            .Where(l => l.AssetId == asset.Id)
                            .AsEnumerable()
                            .FirstOrDefault(l => l.Type == LocatorType.OnDemandOrigin);

            if (streamingLocator != null && streamingLocator.ExpirationDateTime <= DateTime.UtcNow + TimeSpan.FromHours(1))
            {
                streamingLocator.Delete();
                streamingLocator = null;
            }

            if (streamingLocator == null)
            {
                IAccessPolicy accessPolicy = _mediaContext.AccessPolicies.Create("readPolicy", TimeSpan.FromDays(7), AccessPermissions.Read);
                streamingLocator = _mediaContext.Locators.CreateLocator(LocatorType.OnDemandOrigin, asset, accessPolicy);
            }

            streamingLocator.Update(DateTime.Now + TimeSpan.FromDays(7));

            return streamingLocator;
        }

        private static IAssetDeliveryPolicy CreateAssetDeliveryPolicy(IAsset asset, IContentKey key)
        {
            var policy = asset.DeliveryPolicies
                .Where(p => p.AssetDeliveryProtocol == AssetDeliveryProtocol.HLS)
                .SingleOrDefault();

            if (policy != null)
            {
                policy.Delete();
            }

            Uri keyUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.FairPlay);

            var configuration = new Dictionary<AssetDeliveryPolicyConfigurationKey, string>();

            AssetDeliveryPolicyType policyType;

            var kdUrl = keyUrl.ToString().Replace("https://", "skd://");
            configuration.Add(AssetDeliveryPolicyConfigurationKey.FairPlayLicenseAcquisitionUrl, kdUrl);

            var kdPolicy = _mediaContext.ContentKeyAuthorizationPolicies.Where(p => p.Id == key.AuthorizationPolicyId).Single();

            var kdOption = kdPolicy.Options.Single(o => o.KeyDeliveryType == ContentKeyDeliveryType.FairPlay);

            FairPlayConfiguration configFP = JsonConvert.DeserializeObject<FairPlayConfiguration>(kdOption.KeyDeliveryConfiguration);

            configuration.Add(AssetDeliveryPolicyConfigurationKey.CommonEncryptionIVForCbcs, configFP.ContentEncryptionIV);

            policyType = AssetDeliveryPolicyType.DynamicCommonEncryptionCbcs;

            policy = _mediaContext.AssetDeliveryPolicies.Create(
                "FairPlayDeliveryPolicy",
                policyType,
                AssetDeliveryProtocol.HLS,
                configuration);

            return policy;
        }

        private static IContentKey CreateKeyWithPolicy(IAsset asset)
        {
            IContentKey key = asset.ContentKeys.Where(k => k.ContentKeyType == ContentKeyType.CommonEncryptionCbcs).SingleOrDefault();

            if (key != null)
            {
                CleanupKey(key);
            }

            var keyId = Guid.NewGuid();
            byte[] contentKey = Guid.NewGuid().ToByteArray();

            ContentKeyType contentKeyType = ContentKeyType.CommonEncryptionCbcs;
            IContentKeyAuthorizationPolicyOption policyOption;

            var restrictions = new List<ContentKeyAuthorizationPolicyRestriction>
            {
                new ContentKeyAuthorizationPolicyRestriction
                {
                    Name = "Open",
                    KeyRestrictionType = (int)ContentKeyRestrictionType.Open,
                    Requirements = null
                }
            };

            byte[] iv = Guid.NewGuid().ToByteArray();
            policyOption = CreateFairPlayPolicyOption(iv);

            key = _mediaContext.ContentKeys.Create(keyId, contentKey, "TestFairPlayKey", contentKeyType);

            var contentKeyAuthorizationPolicy = _mediaContext.ContentKeyAuthorizationPolicies.CreateAsync("test").Result;
            contentKeyAuthorizationPolicy.Options.Add(policyOption);

            key.AuthorizationPolicyId = contentKeyAuthorizationPolicy.Id;
            key = key.UpdateAsync().Result;

            asset.ContentKeys.Add(key);

            return key;
        }

        private static IContentKeyAuthorizationPolicyOption CreateFairPlayPolicyOption(byte[] iv)
        {
            var appCert = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.Exportable);

            var pfxPasswordId = Guid.NewGuid();
            byte[] pfxPasswordBytes = System.Text.Encoding.UTF8.GetBytes(pfxPassword);
            IContentKey pfxPasswordKey = _mediaContext.ContentKeys.Create(pfxPasswordId, pfxPasswordBytes, "pfxPasswordKey", ContentKeyType.FairPlayPfxPassword);

            var askId = Guid.NewGuid();
            IContentKey askKey = _mediaContext.ContentKeys.Create(askId, askBytes, "askKey", ContentKeyType.FairPlayASk);

            var restriction = new ContentKeyAuthorizationPolicyRestriction
            {
                Name = "Open",
                KeyRestrictionType = (int)ContentKeyRestrictionType.Open,
                Requirements = null
            };

            var restrictions = new List<ContentKeyAuthorizationPolicyRestriction> { restriction };

            string configuration = FairPlayConfiguration.CreateSerializedFairPlayOptionConfiguration(
                appCert,
                pfxPassword,
                pfxPasswordId,
                askId,
                iv);

            var policyOption = _mediaContext.ContentKeyAuthorizationPolicyOptions.Create(
                "fairPlayTest",
                ContentKeyDeliveryType.FairPlay,
                restrictions,
                configuration);

            return policyOption;
        }

        private static IAsset CreateAsset()
        {
            var assetFiles = Directory.GetFiles(_assetFolder);
            var ismFile = assetFiles.Where(file => file.EndsWith(".ism")).Single();
            var assetName = Path.GetFileNameWithoutExtension(ismFile);

            IAsset asset = _mediaContext.Assets.Where(a => a.Name == assetName).SingleOrDefault();

            if (asset != null)
            {
                DeleteAsset(asset);
                asset = null;
            }

            if (asset == null)
            {
                asset = CreateAsset(assetFiles, assetName);
            }

            return asset;
        }

        private static void DeleteAsset(IAsset asset)
        {
            foreach (var locator in asset.Locators.ToArray())
            {
                locator.Delete();
            }
            foreach (var policy in asset.DeliveryPolicies.ToArray())
            {
                asset.DeliveryPolicies.Remove(policy);
                policy.Delete();
            }
            foreach (var key in asset.ContentKeys.ToArray())
            {
                CleanupKey(key);
                asset.ContentKeys.Remove(key);
            }
            asset.Delete();
        }

        private static IAsset CreateAsset(string[] assetFiles, string assetName)
        {
            IAsset asset = _mediaContext.Assets.Create(assetName, AssetCreationOptions.None);

            foreach (var assetFile in assetFiles)
            {
                var assetFileName = Path.GetFileName(assetFile);
                var assetFileCreated = asset.AssetFiles.Create(assetFileName);

                if (assetFileName.EndsWith(".ism"))
                {
                    assetFileCreated.IsPrimary = true;
                    assetFileCreated.Update();
                }

                Console.WriteLine("Created assetFile:{0}, Path:{1}", assetFileCreated.Name, assetFile);
                Console.WriteLine("Upload {0}...", assetFileCreated.Name);

                assetFileCreated.Upload(assetFile);
            }
            return asset;
        }

        public static void CleanupKey(IContentKey key)
        {
            var policy = _mediaContext.ContentKeyAuthorizationPolicies
                .Where(o => o.Id == key.AuthorizationPolicyId)
                .SingleOrDefault();

            if (policy != null)
            {
                if (key.ContentKeyType == ContentKeyType.CommonEncryptionCbcs)
                {
                    string template = policy.Options.Single().KeyDeliveryConfiguration;

                    var config = JsonConvert.DeserializeObject<FairPlayConfiguration>(template);

                    IContentKey ask = _mediaContext
                        .ContentKeys
                        .Where(k => k.Id == _kidPrefix + config.ASkId.ToString())
                        .SingleOrDefault();

                    if (ask != null)
                    {
                        ask.Delete();
                    }

                    IContentKey pfxPassword = _mediaContext
                        .ContentKeys
                        .Where(k => k.Id == _kidPrefix + config.FairPlayPfxPasswordId.ToString())
                        .SingleOrDefault();

                    if (pfxPassword != null)
                    {
                        pfxPassword.Delete();
                    }
                }

                policy.Delete();
            }
        }

        private static IStreamingEndpoint GetOrigin(bool recreate = true)
        {
            string originName = "testfp";

            var origin = _mediaContext.StreamingEndpoints.AsEnumerable().SingleOrDefault(ep => ep.Name == originName);

            if (origin != null && (recreate || origin.ScaleUnits < 1))
            {
                if (origin.State != StreamingEndpointState.Stopped)
                {
                    origin.Stop();
                }

                origin.Delete();
                origin = null;
            }

            if (origin == null)
            {
                Console.WriteLine("Creating endpoint...");
                origin = _mediaContext.StreamingEndpoints.Create(originName, 1);
                Console.WriteLine("Endpoint created...");
            }

            if (origin.State == StreamingEndpointState.Stopped)
            {
                Console.WriteLine("Starting Endpoint...");
                origin.Start();
            }

            origin = WaitForStreamingEndpointStart(origin);
            return origin;
        }

        private static IStreamingEndpoint WaitForStreamingEndpointStart(IStreamingEndpoint origin)
        {
            while (origin.State != StreamingEndpointState.Running)
            {
                Console.WriteLine("Waiting for Endpoint...");
                Thread.Sleep(10000);
                origin = _mediaContext.StreamingEndpoints.AsEnumerable().SingleOrDefault(ep => ep.Id == origin.Id);
            }
            Console.WriteLine("Endpoint started.");
            return origin;
        }

        private static byte[] HexToBytes(string s)
        {
            byte[] result = Enumerable
                .Range(0, s.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(s.Substring(x, 2), 16))
                .ToArray();
            return result;
        }
    }
}
