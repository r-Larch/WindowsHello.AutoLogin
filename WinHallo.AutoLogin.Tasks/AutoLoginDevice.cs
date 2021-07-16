using System;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;


namespace WinHallo.AutoLogin.Tasks {
    public sealed class AutoLoginDevice {
        public string DeviceId { get; set; }

        public string FriendlyName { get; set; }
        public string ModelNumber { get; set; }

        public IBuffer AuthKey { get; set; }
        public IBuffer DeviceKey { get; set; }


        public static AutoLoginDevice NewRandomDevice(string name, string model)
        {
            return new AutoLoginDevice {
                DeviceId = Guid.NewGuid().ToString(),
                DeviceKey = CryptographicBuffer.GenerateRandom(32),
                AuthKey = CryptographicBuffer.GenerateRandom(32),
                FriendlyName = name,
                ModelNumber = model,
            };
        }


        public IBuffer GetConfigData()
        {
            var deviceConfigData = Concat(DeviceKey, AuthKey);

            return deviceConfigData;
        }


        /// <summary>
        /// In real world, you would need to take this nonce and send to companion device to perform an HMAC operation with it
        /// You will have only 20 second to get the HMAC from the companion device
        /// </summary>
        public static AuthResult RunAuthentication(IBuffer sessionNonce, IBuffer deviceNonce, IBuffer deviceConfigData)
        {
            var sha256 = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);

            var (deviceKey, authKey) = Split(deviceConfigData);

            var deviceHmac = Hmac(sha256, key: deviceKey, data: deviceNonce);
            var sessionHmac = Hmac(sha256, key: authKey, data: Concat(deviceHmac, sessionNonce));

            return new AuthResult {
                DeviceHmac = deviceHmac,
                SessionHmac = sessionHmac,
            };
        }


        private static IBuffer Concat(params IBuffer[] buffers)
        {
            var count = buffers.Sum(_ => _.Length);
            var result = new byte[count];
            var i = 0;
            foreach (var buffer in buffers) {
                var src = buffer.ToArray();
                Array.Copy(src, 0, result, i, src.Length);
                i = src.Length;
            }

            return CryptographicBuffer.CreateFromByteArray(result);
        }

        private static (IBuffer deviceKey, IBuffer authKey) Split(IBuffer deviceConfigData)
        {
            if (deviceConfigData.Length != 64) {
                throw new Exception("Invalid deviceConfigData; Expected 64 bytes!");
            }

            var deviceKey = new byte[32];
            var authKey = new byte[32];
            deviceConfigData.CopyTo(0, deviceKey, 0, 32);
            deviceConfigData.CopyTo(32, authKey, 0, 32);

            return (
                deviceKey: CryptographicBuffer.CreateFromByteArray(deviceKey),
                authKey: CryptographicBuffer.CreateFromByteArray(authKey)
            );
        }

        private static IBuffer Hmac(MacAlgorithmProvider provider, IBuffer key, IBuffer data)
        {
            return CryptographicEngine.Sign(provider.CreateKey(key), data);
        }
    }

    public sealed class AuthResult {
        public IBuffer DeviceHmac { get; set; }
        public IBuffer SessionHmac { get; set; }
    }
}
