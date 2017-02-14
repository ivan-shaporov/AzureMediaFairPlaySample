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
using Newtonsoft.Json;

namespace CreateWidevineProtectedAsset
{
    class Program
    {
        private static readonly Uri _wamsEndpoint = new Uri("https://<WAMS endpoint host>.cloudapp.net/");
        private static readonly string _wamsAccount = "<your WAMS account name>";
        private static readonly string _wamsAccountKey = "<your WAMS account key>";
        private static readonly string _wamsAcsBaseAddress = "https://<WAMS ACS host>.accesscontrol.windows.net/";
        private static readonly string _wamsAcsScope = "<WAMS ACS scope>";

        private static readonly string _assetFolder = "<path to the folder with your asset files>";
        
        private static CloudMediaContext _mediaContext;

        static void Main(string[] args)
        {
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

            string keyDeliveryUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.Widevine).ToString();

            Console.WriteLine("ism: {0}\nkey delivery: {1}", uri, keyDeliveryUrl);

            Console.ReadKey();
        }

        private static Uri GetManifestUrl(IStreamingEndpoint origin, IAsset asset, ILocator streamingLocator)
        {
            string manifestFormat = "(format=mpd-time-csf)";

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

            Uri keyUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.Widevine);

            var configuration = new Dictionary<AssetDeliveryPolicyConfigurationKey, string>();

            configuration.Add(AssetDeliveryPolicyConfigurationKey.WidevineLicenseAcquisitionUrl, keyUrl.ToString());

            policy = _mediaContext.AssetDeliveryPolicies.Create(
                "WidevineDeliveryPolicy",
                AssetDeliveryPolicyType.DynamicCommonEncryption,
                AssetDeliveryProtocol.Dash,
                configuration);

            return policy;
        }

        private static IContentKey CreateKeyWithPolicy(IAsset asset)
        {
            IContentKey key = asset.ContentKeys.Where(k => k.ContentKeyType == ContentKeyType.CommonEncryption).SingleOrDefault();

            if (key != null)
            {
                CleanupKey(key);
                key.Delete();
            }

            var keyId = Guid.NewGuid();
            byte[] contentKey = Guid.NewGuid().ToByteArray();

            ContentKeyType contentKeyType = ContentKeyType.CommonEncryption;
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

            string configuration = "{}";
            //string configuration = "{\"allowed_track_types\":\"SD_HD\",\"content_key_specs\":[{\"track_type\":\"SD\",\"security_level\":1,\"required_output_protection\":{\"hdcp\":\"HDCP_NONE\"}}],\"policy_overrides\":{\"can_play\":true,\"can_persist\":true,\"can_renew\":false}}";

            policyOption = _mediaContext.ContentKeyAuthorizationPolicyOptions.Create(
                "widevinetest",
                ContentKeyDeliveryType.Widevine,
                restrictions,
                configuration);

            key = _mediaContext.ContentKeys.Create(keyId, contentKey, "TestWidevineKey", contentKeyType);

            var contentKeyAuthorizationPolicy = _mediaContext.ContentKeyAuthorizationPolicies.CreateAsync("test").Result;
            contentKeyAuthorizationPolicy.Options.Add(policyOption);

            key.AuthorizationPolicyId = contentKeyAuthorizationPolicy.Id;
            key = key.UpdateAsync().Result;

            asset.ContentKeys.Add(key);

            return key;
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
                policy.Delete();
            }
        }

        private static IStreamingEndpoint GetOrigin(bool recreate = true)
        {
            string originName = "testwv";

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
    }
}
