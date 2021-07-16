using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;


namespace Tasks {
    public sealed class MyDevice {
        public string DeviceId { get; } = "6a2877cd-8706-4e0c-bb78-181391ad8100";

        public string FriendlyName { get; } = "Test Simulator";
        public string ModelNumber { get; } = "Sample A1";

        public IBuffer AuthKey { get; }
        public IBuffer DeviceKey { get; }

        public MyDevice()
        {
            DeviceKey = CryptographicBuffer.DecodeFromHexString("1820614efeb71dbaebc315801a2782df26c236e0395f24fbe96344785fbe1a35");
            AuthKey = CryptographicBuffer.DecodeFromHexString("ad76bd149e4762dcd36725f2a5b86d0e5fd1058f7670415b9b5088354d1dd07f");
        }


        public IBuffer GetConfigData()
        {
            var deviceConfigData = Concat(DeviceKey, AuthKey);

            return deviceConfigData;
        }


        /// <summary>
        /// May not take longer then 20sec
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
