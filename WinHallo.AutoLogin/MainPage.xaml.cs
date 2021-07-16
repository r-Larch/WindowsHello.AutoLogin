using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Windows.ApplicationModel.Background;
using Windows.Security.Authentication.Identity.Provider;
using Windows.Storage;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;
using WinHallo.AutoLogin.Tasks;


namespace WinHallo.AutoLogin {
    public sealed partial class MainPage : Page {
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
            DeviceListBox_OnSelectionChanged(null, null);
        }

        private async Task RefreshDeviceList()
        {
            var deviceList = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(SecondaryAuthenticationFactorDeviceFindScope.User);

            DeviceListBox.Items.Clear();

            var remove = new Command<ListDevice>(async device => {
                await SecondaryAuthenticationFactorRegistration.UnregisterDeviceAsync(device.DeviceId);

                if (SelectedDeviceId == device.DeviceId) {
                    SelectedDeviceId = null;
                }

                await RefreshDeviceList();
            });

            foreach (var device in deviceList) {
                var item = new ListDevice {
                    DeviceId = device.DeviceId,
                    Name = $"{device.DeviceFriendlyName} {device.DeviceModelNumber}",
                    RemoveDeviceCommand = remove,
                };

                DeviceListBox.Items.Add(item);

                if (SelectedDeviceId == item.DeviceId) {
                    DeviceListBox.SelectedItem = item;
                }
            }
        }

        private async void RegisterDevice_Click(object sender, RoutedEventArgs e)
        {
            var device = AutoLoginDevice.NewRandomDevice("Auto Login Device", "v1");
            var deviceConfigData = device.GetConfigData();


            var registration = await SecondaryAuthenticationFactorRegistration.RequestStartRegisteringDeviceAsync(
                device.DeviceId,
                capabilities: SecondaryAuthenticationFactorDeviceCapabilities.SecureStorage,
                device.FriendlyName,
                device.ModelNumber,
                device.DeviceKey,
                device.AuthKey
            );


            switch (registration.Status) {
                case SecondaryAuthenticationFactorRegistrationStatus.Started:
                    await registration.Registration.FinishRegisteringDeviceAsync(deviceConfigData);

                    if (string.IsNullOrEmpty(SelectedDeviceId)) {
                        SelectedDeviceId = device.DeviceId;
                    }

                    await RefreshDeviceList();
                    break;
                case SecondaryAuthenticationFactorRegistrationStatus.DisabledByPolicy:
                    //For DisaledByPolicy Exception:Ensure secondary auth is enabled.
                    //Use GPEdit.msc to update group policy to allow secondary auth
                    //Local Computer Policy\Computer Configuration\Administrative Templates\Windows Components\Microsoft Secondary Authentication Factor\Allow Companion device for secondary authentication
                    await new MessageDialog("Disabled by Policy.  Please update the policy and try again.").ShowAsync();
                    break;
                case SecondaryAuthenticationFactorRegistrationStatus.PinSetupRequired:
                    //For PinSetupRequired Exception:Ensure PIN is setup on the device
                    //Either use gpedit.msc or set reg key
                    //This setting can be enabled by creating the AllowDomainPINLogon REG_DWORD value under the HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System Registry key and setting it to 1.
                    await new MessageDialog("Please setup PIN for your device and try again.").ShowAsync();
                    break;
                case SecondaryAuthenticationFactorRegistrationStatus.CanceledByUser:
                    // ..
                    break;
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

            var taskType = typeof(WinHallo.AutoLogin.Tasks.AutoLoginBackgroundTask);

            foreach (var task in BackgroundTaskRegistration.AllTasks) {
                if (task.Value.Name == taskType.Name) {
                    task.Value.Unregister(true);
                    break;
                }
            }

            if (access == BackgroundAccessStatus.AllowedSubjectToSystemPolicy) {
                var builder = new BackgroundTaskBuilder {
                    Name = taskType.Name,
                    TaskEntryPoint = taskType.FullName,
                };

                builder.SetTrigger(new SecondaryAuthenticationFactorAuthenticationTrigger());

                var register = builder.Register();

                TaskRegistered.Visibility = Visibility.Visible;
            }
        }

        private void DeviceListBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (DeviceListBox.SelectedItem is ListDevice device) {
                SelectedDeviceId = device.DeviceId;
                SelectedDeviceName.Text = device.Name;
                SelectedDevice.Text = device.DeviceId;
            }
            else {
                SelectedDeviceName.Text = "No Device Selected";
                SelectedDevice.Text = "Please add and select a Device";
            }
        }
    }

    internal class ListDevice {
        public string DeviceId { get; set; }
        public string Name { get; set; }
        public ICommand RemoveDeviceCommand { get; set; }
    }

    internal class Command<T> : ICommand {
        private readonly Func<T, Task> _action;
        public Command(Func<T, Task> action) => _action = action;
        public static Command<T> From(Func<T, Task> action) => new Command<T>(action);
        public void Execute(object parameter) => _action((T) parameter);
        public bool CanExecute(object parameter) => true;
        public event EventHandler CanExecuteChanged;
    }
}
