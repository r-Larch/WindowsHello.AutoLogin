using System;
using System.Linq;
using System.Threading;
using Windows.ApplicationModel.Background;
using Windows.Data.Xml.Dom;
using Windows.Security.Authentication.Identity.Provider;
using Windows.Security.Cryptography;
using Windows.Storage;
using Windows.UI.Notifications;


namespace WinHallo.AutoLogin.Tasks {
    public sealed class AutoLoginBackgroundTask : IBackgroundTask {
        private ManualResetEvent _opCompletedEvent;
        private readonly Logger _log = new Logger();


        public void Run(IBackgroundTaskInstance taskInstance)
        {
            var deferral = taskInstance.GetDeferral();

            _opCompletedEvent = new ManualResetEvent(false);

            SecondaryAuthenticationFactorAuthentication.AuthenticationStageChanged += OnStageChanged;

            _opCompletedEvent.WaitOne();

            deferral.Complete();
        }


        private async void OnStageChanged(object sender, SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs args)
        {
            var stage = args.StageInfo.Stage;

            if (stage == SecondaryAuthenticationFactorAuthenticationStage.WaitingForUserConfirmation) {
                await SecondaryAuthenticationFactorAuthentication.ShowNotificationMessageAsync(
                    deviceName: "Auto Login",
                    message: SecondaryAuthenticationFactorAuthenticationMessage.SwipeUpWelcome
                );
            }

            else if (stage == SecondaryAuthenticationFactorAuthenticationStage.CollectingCredential) {
                PerformAuthentication();
            }

            else if (stage == SecondaryAuthenticationFactorAuthenticationStage.StoppingAuthentication) {
                SecondaryAuthenticationFactorAuthentication.AuthenticationStageChanged -= OnStageChanged;
                _opCompletedEvent.Set();
            }
        }


        private async void PerformAuthentication()
        {
            var stageInfo = await SecondaryAuthenticationFactorAuthentication.GetAuthenticationStageInfoAsync();

            if (stageInfo.Stage != SecondaryAuthenticationFactorAuthenticationStage.CollectingCredential) {
                ShowToastNotification($"Unexpected! Stage was: {stageInfo.Stage}");
                return;
            }

            var deviceId = ApplicationData.Current.LocalSettings.Values["SelectedDevice"] as string;

            var devices = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(SecondaryAuthenticationFactorDeviceFindScope.AllUsers);
            var device = devices.FirstOrDefault(_ => _.DeviceId == deviceId);

            if (device == null) {
                ShowToastNotification($"Device Not Found - ID:{deviceId ?? "<null>"}");
                return;
            }

            // Generate a nonce and do a HMAC operation with the nonce
            var svcNonce = CryptographicBuffer.GenerateRandom(32);

            var authResult = await SecondaryAuthenticationFactorAuthentication.StartAuthenticationAsync(device.DeviceId, svcNonce);

            if (authResult.Status != SecondaryAuthenticationFactorAuthenticationStatus.Started) {
                var error = $"Unexpected! Could not start authentication! Status was: {authResult.Status}";
                ShowToastNotification(error);
                await authResult.Authentication.AbortAuthenticationAsync(error);
                return;
            }

            var hmac = AutoLoginDevice.RunAuthentication(
                sessionNonce: authResult.Authentication.SessionNonce,
                deviceNonce: authResult.Authentication.DeviceNonce,
                deviceConfigData: authResult.Authentication.DeviceConfigurationData
            );

            var authStatus = await authResult.Authentication.FinishAuthenticationAsync(hmac.DeviceHmac, hmac.SessionHmac);

            if (authStatus != SecondaryAuthenticationFactorFinishAuthenticationStatus.Completed) {
                var error = $"Unable to complete authentication! Status was: {authResult.Status}";
                ShowToastNotification(error);
                await authResult.Authentication.AbortAuthenticationAsync(error);
                return;
            }
        }


        private string _message;

        public void ShowToastNotification(string message)
        {
            _log.Log(message);
            message = _message += $"{message}\r\n";

            var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastImageAndText01);

            // Set Text
            var toastTextElements = toastXml.GetElementsByTagName("text");
            toastTextElements[0].AppendChild(toastXml.CreateTextNode(message));

            // Set image
            // Images must be less than 200 KB in size and smaller than 1024 x 1024 pixels.
            var toastImageAttributes = toastXml.GetElementsByTagName("image");
            ((XmlElement) toastImageAttributes[0]).SetAttribute("src", "ms-appx:///Images/logo-80px-80px.png");
            ((XmlElement) toastImageAttributes[0]).SetAttribute("alt", "logo");

            // toast duration
            var toastNode = toastXml.SelectSingleNode("/toast");
            ((XmlElement) toastNode).SetAttribute("duration", "short");

            // toast navigation
            var toastNavigationUriString = "#/MainPage.xaml?param1=12345";
            var toastElement = (XmlElement) toastXml.SelectSingleNode("/toast");
            toastElement.SetAttribute("launch", toastNavigationUriString);

            // Create the toast notification based on the XML content you've specified.
            var toast = new ToastNotification(toastXml);

            // Send your toast notification.
            ToastNotificationManager.CreateToastNotifier().Show(toast);
        }
    }
}
