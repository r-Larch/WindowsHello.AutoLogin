using System;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;


namespace Tasks {
    public sealed class MyDevice {
        public static MyDevice Default { get; } = new MyDevice();

        public string DeviceId { get; } = "6a2877cd-8706-4e0c-bb78-181391ad8100";

        public IBuffer AuthKey { get; }
        public IBuffer DeviceKey { get; }

        public string FriendlyName { get; } = "Test Simulator";
        public string ModelNumber { get; } = "Sample A1";

        private MyDevice()
        {
            DeviceKey = CryptographicBuffer.DecodeFromHexString("1820614efeb71dbaebc315801a2782df26c236e0395f24fbe96344785fbe1a35");
            AuthKey = CryptographicBuffer.DecodeFromHexString("ad76bd149e4762dcd36725f2a5b86d0e5fd1058f7670415b9b5088354d1dd07f");
        }


        public IBuffer GetConfigData()
        {
            //
            // WARNING: Test code
            // The keys SHOULD NOT be saved into device config data
            //
            byte[] deviceKeyArray = {0};
            CryptographicBuffer.CopyToByteArray(DeviceKey, out deviceKeyArray);

            byte[] authKeyArray = {0};
            CryptographicBuffer.CopyToByteArray(AuthKey, out authKeyArray);

            //Generate combinedDataArray
            var combinedDataArraySize = deviceKeyArray.Length + authKeyArray.Length;
            var combinedDataArray = new byte[combinedDataArraySize];
            for (var index = 0; index < deviceKeyArray.Length; index++) {
                combinedDataArray[index] = deviceKeyArray[index];
            }

            for (var index = 0; index < authKeyArray.Length; index++) {
                combinedDataArray[deviceKeyArray.Length + index] = authKeyArray[index];
            }

            // Get a Ibuffer from combinedDataArray
            var deviceConfigData = CryptographicBuffer.CreateFromByteArray(combinedDataArray);

            return deviceConfigData;
        }


        /// <summary>
        /// May not take longer then 20sec
        /// In real world, you would need to take this nonce and send to companion device to perform an HMAC operation with it
        /// You will have only 20 second to get the HMAC from the companion device
        /// </summary>
        public static AuthResult RunAuthentication(IBuffer sessionNonce, IBuffer deviceNonce, IBuffer deviceConfigData)
        {
            // var (deviceKey, authKey) = parse(deviceConfigData);

            // var deviceHmac = HMAC(deviceKey, deviceNonce)
            // var sessionHmac = HMAC(authKey, deviceHmac + sessionNonce)

            //
            // WARNING: Test code
            // The HAMC calculation SHOULD be done on companion device
            //
            CryptographicBuffer.CopyToByteArray(deviceConfigData, out var combinedDataArray);

            var deviceKeyArray = new byte[32];
            var authKeyArray = new byte[32];

            for (var index = 0; index < deviceKeyArray.Length; index++) {
                deviceKeyArray[index] = combinedDataArray[index];
            }

            for (var index = 0; index < authKeyArray.Length; index++) {
                authKeyArray[index] = combinedDataArray[deviceKeyArray.Length + index];
            }

            // Create device key and authentication key
            var deviceKey = CryptographicBuffer.CreateFromByteArray(deviceKeyArray);
            var authKey = CryptographicBuffer.CreateFromByteArray(authKeyArray);

            // Calculate the HMAC
            var hMACSha256Provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);

            var deviceHmac = CryptographicEngine.Sign(hMACSha256Provider.CreateKey(deviceKey), deviceNonce);

            byte[] deviceHmacArray = {0};
            CryptographicBuffer.CopyToByteArray(deviceHmac, out deviceHmacArray);

            byte[] sessionNonceArray = {0};
            CryptographicBuffer.CopyToByteArray(sessionNonce, out sessionNonceArray);

            combinedDataArray = new byte[deviceHmacArray.Length + sessionNonceArray.Length];
            for (var index = 0; index < deviceHmacArray.Length; index++) {
                combinedDataArray[index] = deviceHmacArray[index];
            }

            for (var index = 0; index < sessionNonceArray.Length; index++) {
                combinedDataArray[deviceHmacArray.Length + index] = sessionNonceArray[index];
            }

            // Get a Ibuffer from combinedDataArray
            var sessionMessage = CryptographicBuffer.CreateFromByteArray(combinedDataArray);

            // Calculate sessionHmac
            var sessionHmac = CryptographicEngine.Sign(hMACSha256Provider.CreateKey(authKey), sessionMessage);

            return new AuthResult {
                DeviceHmac = deviceHmac,
                SessionHmac = sessionHmac,
            };
        }
    }

    public sealed class AuthResult {
        public IBuffer DeviceHmac { get; set; }
        public IBuffer SessionHmac { get; set; }
    }
}
