using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Windows.ApplicationModel.Core;
using Windows.Security.Authentication.Identity.Provider;
using Windows.Storage;
using Windows.UI.Core;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;
using Tasks;


namespace CDFSampleApp_Ashish {
    public sealed partial class MainPage : Page {
        private const string MyBgTaskName = "myBGTask";
        private const string MyBgTaskEntryPoint = "Tasks.myBGTask";

        internal string SelectedDeviceId {
            get => ApplicationData.Current.LocalSettings.Values["SelectedDevice"] as string;
            set => ApplicationData.Current.LocalSettings.Values["SelectedDevice"] = value;
        }

        public MainPage()
        {
            InitializeComponent();
            DataContext = this;
        }

        protected override async void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);

            await RefreshDeviceList();
        }

        private async Task RefreshDeviceList()
        {
            var deviceList = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(SecondaryAuthenticationFactorDeviceFindScope.User);

            DeviceListBox.Items.Clear();

            foreach (var deviceInfo in deviceList) {
                DeviceListBox.Items.Add(deviceInfo.DeviceId);
                if (SelectedDeviceId == deviceInfo.DeviceId) {
                    DeviceListBox.SelectedItem = deviceInfo.DeviceId;
                }
            }
        }

        private async void RegisterDevice_Click(object sender, RoutedEventArgs e)
        {
            var device = new MyDevice();

            var registration = await SecondaryAuthenticationFactorRegistration.RequestStartRegisteringDeviceAsync(
                device.DeviceId,
                capabilities: SecondaryAuthenticationFactorDeviceCapabilities.SecureStorage,
                device.FriendlyName,
                device.ModelNumber,
                device.DeviceKey,
                device.AuthKey
            );

            if (registration.Status != SecondaryAuthenticationFactorRegistrationStatus.Started) {
                if (registration.Status == SecondaryAuthenticationFactorRegistrationStatus.DisabledByPolicy) {
                    //For DisaledByPolicy Exception:Ensure secondary auth is enabled.
                    //Use GPEdit.msc to update group policy to allow secondary auth
                    //Local Computer Policy\Computer Configuration\Administrative Templates\Windows Components\Microsoft Secondary Authentication Factor\Allow Companion device for secondary authentication
                    await new MessageDialog("Disabled by Policy.  Please update the policy and try again.").ShowAsync();
                    return;
                }

                if (registration.Status == SecondaryAuthenticationFactorRegistrationStatus.PinSetupRequired) {
                    //For PinSetupRequired Exception:Ensure PIN is setup on the device
                    //Either use gpedit.msc or set reg key
                    //This setting can be enabled by creating the AllowDomainPINLogon REG_DWORD value under the HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System Registry key and setting it to 1.
                    await new MessageDialog("Please setup PIN for your device and try again.").ShowAsync();
                    return;
                }
            }

            Debug.WriteLine("Device Registration Started!");

            var deviceConfigData = device.GetConfigData();
            await registration.Registration.FinishRegisteringDeviceAsync(deviceConfigData);

            await RefreshDeviceList();
        }


        private async void UnregisterDevice_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(SelectedDeviceId)) {
                //InfoList.Items.Add("Unregister a device:");

                await SecondaryAuthenticationFactorRegistration.UnregisterDeviceAsync(SelectedDeviceId);

                //InfoList.Items.Add("Device unregistration is completed.");

                await RefreshDeviceList();
            }
        }


        private void RegisterBgTask_Click(object sender, RoutedEventArgs e)
        {
            RegisterTask();
        }


        private async void RegisterTask()
        {
            TaskRegistered.Visibility = Visibility.Collapsed;
            ErrorMsg.Visibility = Visibility.Collapsed;

            if (string.IsNullOrEmpty(SelectedDeviceId)) {
                ErrorMsg.Visibility = Visibility.Visible;
                return;
            }

            BackgroundExecutionManager.RemoveAccess();
            var access = await BackgroundExecutionManager.RequestAccessAsync();

            foreach (var task in BackgroundTaskRegistration.AllTasks) {
                if (task.Value.Name == MyBgTaskName) {
                    task.Value.Unregister(true);
                    break;
                }
            }

            if (access == BackgroundAccessStatus.AllowedSubjectToSystemPolicy) {
                var builder = new BackgroundTaskBuilder {
                    Name = MyBgTaskName,
                    TaskEntryPoint = MyBgTaskEntryPoint,
                };

                builder.SetTrigger(new SecondaryAuthenticationFactorAuthenticationTrigger());

                var register = builder.Register();

                register.Progress += (sender, args) => {
                    //// Handle background task progress.
                    //if (args.Progress == 1) {
                    //    await CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () => {
                    //        Debug.WriteLine("Background task is started.");
                    //    });
                    //}
                };
                register.Completed += (sender, args) => {
                    Debug.WriteLine("Background task registration is completed.");

                    _ = CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () => {
                        TaskRegistered.Visibility = Visibility.Visible;
                    });
                };

                TaskRegistered.Visibility = Visibility.Visible;
            }
        }


        private void DeviceListBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            SelectedDevice.Text = SelectedDeviceId = DeviceListBox.SelectedItem?.ToString() ?? string.Empty;
        }
    }
}
