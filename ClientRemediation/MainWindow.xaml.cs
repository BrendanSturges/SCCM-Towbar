using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Forms;
using System.Windows.Controls;
using System.Windows.Input;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel;



namespace SCCMTowbar
{
    public partial class MainWindow : Window
    {
        // Define logic via functions
        public void TriggerSchedule(string computerName, string ID)
        {

            //create connection to root\ccm\sms_client on a remote system
            ManagementScope scp = new ManagementScope(string.Format(@"\\{0}\root\ccm", computerName));
            ManagementClass cls = new ManagementClass(scp.Path.Path, "sms_client", null);
            ManagementBaseObject inParams;

            //run the schedule defined in the checkboxes
            inParams = cls.GetMethodParameters("TriggerSchedule");
            inParams["sScheduleID"] = "{" + ID + "}";
            ManagementBaseObject outMPParams = cls.InvokeMethod("TriggerSchedule", inParams, null);
        }

        public bool PingHost(string nameOrAddress)
        {
            bool pingable = false;
            Ping pinger = new Ping();
            try
            {
                PingReply reply = pinger.Send(nameOrAddress);
                pingable = reply.Status == IPStatus.Success;
                return pingable;
            }
            catch (PingException)
            {
                // Discard PingExceptions and return false;
                return false;
            }
        }

        public void checkSite(string computerName)
        {
            ManagementScope scp = new ManagementScope(string.Format(@"\\{0}\root\ccm", computerName));
            ManagementClass cls = new ManagementClass(scp.Path.Path, "sms_client", null);

            // Get current site code.
            ManagementBaseObject outSiteParams = cls.InvokeMethod("GetAssignedSite", null, null);

            // Display current site code.
            Console.AppendText(computerName + " Site Code: " + outSiteParams["sSiteCode"].ToString() + Environment.NewLine);
        }

        public void checkReboot(string computerName)
        {
            ManagementScope scp = new ManagementScope(string.Format(@"\\{0}\root\ccm\clientsdk", computerName));
            ManagementClass cls = new ManagementClass(scp.Path.Path, "ccm_clientutilities", null);

            // Get the reboot status
            ManagementBaseObject outSiteParams = cls.InvokeMethod("DetermineIfRebootPending", null, null);

            // Display the status
            Console.AppendText(computerName + " Reboot Pending: " + outSiteParams["RebootPending"].ToString() + Environment.NewLine);
        }

        public static string GetIP4Address(string computerName)
        {
            string IP4Address = String.Empty;

            foreach (IPAddress IPA in Dns.GetHostAddresses(computerName))
            {
                if (IPA.AddressFamily == AddressFamily.InterNetwork)
                {
                    IP4Address = IPA.ToString();
                    break;
                }
            }

            return IP4Address;
        }

        public void checkDNS(string computerName)
        {
            
            string addy = GetIP4Address(computerName);

            //get the DNS entry for the ipv4 address
            IPHostEntry entry = Dns.GetHostEntry(addy);
            //convert address to string, split the string at '.' and drop the FQDN from the end for comparison purposes
            string addyString = entry.HostName.ToString();
            string[] dropFQDN = addyString.Split('.');
            string fetchedDNS = dropFQDN[0];

            //string fetchedDNS = getDomain(computerName, 1);
            //compare user input to fetched DNS from the IP assigned & converts both strings to upper case first as a sanity check
            if(computerName.ToUpper() == addyString.ToUpper())
            {
                Console.AppendText(computerName + " DNS is OK, " + addy + " is assigned to " + computerName + Environment.NewLine);
            }
            else
            {
                Console.AppendText(computerName + " DNS does not match, " + addy + " is assigned to " + fetchedDNS.ToUpper() + Environment.NewLine);
            }

        }

        public string getDomain(string computerName, int i)
        {
            string addy = GetIP4Address(computerName);
            //get the DNS entry for the ipv4 address
            IPHostEntry entry = Dns.GetHostEntry(addy);
            //convert address to string, split the string at '.' and drop the FQDN from the end for comparison purposes
            string addyString = entry.HostName.ToString();
            string[] dropFQDN = addyString.Split('.');
            return dropFQDN[i];
        }

        public void checkPatches(string computerName, int evalState)
        {
            ManagementScope scp = new ManagementScope(string.Format(@"\\{0}\root\ccm\clientsdk", computerName));
            ManagementClass cls = new ManagementClass(@"CCM_SoftwareUpdateManager");

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(string.Format("SELECT * FROM CCM_SOFTWAREUPDATE WHERE EVALUATIONSTATE = {0}", evalState));

            cls.Scope = searcher.Scope = scp;

            ManagementObjectCollection collection = searcher.Get();
            List<ManagementObject> lUpdates = new List<ManagementObject>();

            int counter = 0;

            foreach (ManagementObject o in collection)
            {
                object[] args = { o };

                object[] methodArgs = { args, null };

                Console.AppendText(o.Properties["Name"].Value + Environment.NewLine);
                counter++;
            }
            Console.AppendText("Number of patches available: " + counter + Environment.NewLine);
        }

        public void patchEverything(string computerName)
        {
            ManagementScope sc = new ManagementScope(string.Format(@"\\{0}\root\ccm\clientsdk", computerName));
            ManagementClass c = new ManagementClass(@"CCM_SoftwareUpdatesManager");
            ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT * FROM CCM_SOFTWAREUPDATE WHERE COMPLIANCESTATE=0 AND EVALUATIONSTATE < 2");
            c.Scope = s.Scope = sc;

            ManagementObjectCollection col = s.Get();
            List<ManagementObject> lUpdates = new List<ManagementObject>();

            int index = 1;

            foreach (ManagementObject o in col)
            {

                System.Management.ManagementBaseObject[] args = { o };

                object[] methodArgs = { args };

                c.InvokeMethod("InstallUpdates", methodArgs);

                System.Windows.Application.Current.Dispatcher.Invoke((Action)(() =>
                {
                    Console.AppendText(computerName + ": Now Installing Update " + index + " of " + col.Count + Environment.NewLine);
                }));
                

                UInt32 evalState = 0;
                
                
                while (evalState < 7)
                {

                    try
                    {
                        o.Get();
                        evalState = (UInt32)o.Properties["EvaluationState"].Value;
                    }

                    catch
                    {
                        break;
                    }

                }
                System.Windows.Application.Current.Dispatcher.Invoke((Action)(() =>
                {
                    Console.AppendText(computerName + ": Update " + index + " of " + col.Count + " completed" + Environment.NewLine);
                }));

                index++;
            }
        }

        public void rebootSystem(string computerName)
        {
            System.Diagnostics.Process.Start("shutdown.exe", "-r -t 0 -f -m \\" + computerName);
            Console.AppendText(computerName + " is rebooting now" + Environment.NewLine);
        }

        public void getAppliedPatches(string computerName, int days)
        {
            //computerName = getFQDN(computerName);
            EventLog ev = new EventLog("System", computerName);
            DateTime t1 = DateTime.Now;
            DateTime fromDate = DateTime.Now.AddDays(-days);
            int i = 0;

            for (i = ev.Entries.Count - 1; i >= 0; i--)
            {
                if (ev.Entries[i].InstanceId == 19 && ev.Entries[i].TimeGenerated > fromDate)
                {
                    Console.AppendText(computerName + " " + ev.Entries[i].TimeGenerated + " " + ev.Entries[i].InstanceId + " " + ev.Entries[i].Message + Environment.NewLine);
                }
            }
            Console.AppendText("End of log entries" + Environment.NewLine);
        }

        public MainWindow()
        {
            InitializeComponent();
        }


        private void checkBox_Checked(object sender, RoutedEventArgs e)
        {

        }

        public void textBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }
        
        public class WaitCursor : IDisposable
        {
            private System.Windows.Input.Cursor _previousCursor;

            public WaitCursor()
            {
                _previousCursor = Mouse.OverrideCursor;

                Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
            }

            #region IDisposable Members

            public void Dispose()
            {
                Mouse.OverrideCursor = _previousCursor;
            }

            #endregion
        }

        public string getFQDN(string computername, bool pingMe)
        {
            if(pingMe == true)
            {
                System.Net.IPHostEntry FQDN = Dns.GetHostEntry(computername);
                string getMe = FQDN.HostName;
                return getMe;
            }
            else
            {
                return computername;
            }
            
        }

        public static TimeSpan GetUptime(string computerName)
        {
            ManagementObject mo = new ManagementObject(string.Format(@"\\{0}\root\cimv2:Win32_OperatingSystem=@", computerName));
            DateTime lastBootUp = ManagementDateTimeConverter.ToDateTime(mo["LastBootUpTime"].ToString());
            TimeSpan Uptime = DateTime.Now.ToUniversalTime() - lastBootUp.ToUniversalTime();
            //Console.AppendText(Uptime + Environment.NewLine);
            return Uptime;
        }

        // UI Hooks
        private void Computer_List_GotFocus(object sender, RoutedEventArgs e)
        {
            //click in the system list to clear it, only works the first time to purge the "Client Name" holder text
            Computer_List.Text = "";
            Computer_List.GotFocus -= Computer_List_GotFocus;
        }

        private void File_NewList_Click(object sender, RoutedEventArgs e)
        {
            // removes all data from system list
            Computer_List.Text = "";
        }

        private void File_ClearCon_Click(object sender, RoutedEventArgs e)
        {
            //clear the console
            Console.Text = "";
        }

        private void File_OpenFile_Click(object sender, RoutedEventArgs e)
        {
            //opens .txt files full of system names
            OpenFileDialog getList = new OpenFileDialog();
            getList.Title = "Open Text File";
            getList.FileName = "";
            getList.InitialDirectory = @"C:\";

            DialogResult holdIt = getList.ShowDialog();
            string sardine = getList.FileName;
            string readIt = File.ReadAllText(sardine);
            Computer_List.Text = readIt;
        }

        private void File_Quit_Click(object sender, RoutedEventArgs e)
        {
            //closes the application
            System.Windows.Application.Current.Shutdown();
        }

        private void File_Save_Computer_List_Click(object sender, RoutedEventArgs e)
        {
            //save computer list to txt
            SaveFileDialog saveMe = new SaveFileDialog()
            {
                Filter = "Text Files(*.txt)|*.txt|All(*.*)|*"
            };

            if (saveMe.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                System.IO.File.WriteAllText(saveMe.FileName, Computer_List.Text);
            }
        }

        private void File_Export_Console_Click(object sender, RoutedEventArgs e)
        {
            //save current console to .txt
            SaveFileDialog saveMe = new SaveFileDialog()
            {
                Filter = "Text Files(*.txt)|*.txt|All(*.*)|*"
            };

            if (saveMe.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                System.IO.File.WriteAllText(saveMe.FileName, Console.Text);
            }

        }

        private void Help_About_Click(object sender, RoutedEventArgs e)
        {
            //help file popup so users know who to blame
            System.Windows.Forms.MessageBox.Show("Version 1.3" + Environment.NewLine + "Send your complaints to: brendansturges@gmail.com");
        }

        private void Options_Plane_Click(object sender, RoutedEventArgs e)
        {
            DialogResult Plane = System.Windows.Forms.MessageBox.Show("Bruh I'm just an ascii plane");
        }

        private void Options_Uncheck_All_Click(object sender, RoutedEventArgs e)
        {
            // this is _AWFUL_ and needs to be retooled
            Software_Inventory.IsChecked = false;
            Hardware_Inventory.IsChecked = false;
            Heartbeat.IsChecked = false;
            Request_Machine_Policy.IsChecked = false;
            Force_Update_Scan.IsChecked = false;
            Refresh_Location_Services.IsChecked = false;
            Evaluate_Machine_Policy_Assignments.IsChecked = false;
            Ping_Status.IsChecked = false;
            Reboot_Status.IsChecked = false;
            Check_SCCM_Site.IsChecked = false;
            Check_DNS_Status.IsChecked = false;
            Get_Available_Patches.IsChecked = false;
            Get_Failed_Patches.IsChecked = false;
            Apply_Available_Patches.IsChecked = false;
            //Reboot_All_Servers.IsChecked = false;
            Get_Applied_Patches.IsChecked = false;
            Get_FQDN.IsChecked = false;
            check_uptime.IsChecked = false;
        }

        private void verify_infra_services(object sender, RoutedEventArgs e)
        {
            /*
            BITS
            IISADMIN
            W3SVC

            SMS_EXECUTIVE
            CCMEXEC
            SMS_NOTIFICATION_SERVER
            SMS_SITE_COMPONENT_MANAGER
            SMS_SITE_VSS_WRITER

            MSSQLSERVER
            SQLSERVERAGENT
            SQLBROWSER
            SQLWRITER
            REPORTWRITER

            SMS_SITE_SQL_BACKUP_PRIMARY***
            SMS_SITE_SQL_BACKUP_PRIMARY_DEV***
            */

        }

        // Big 'Red' Button
        public async void button_Click(object sender, RoutedEventArgs e)
        {
            //parse system list into an list of strings so we can forloop it
            List<string> serverList = Computer_List.Text.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries).Select(p => p.Trim()).ToList();

            //sets up a way to prevent having to click Yes for every single server in the list for Get_Applied_Patches, Get_Available_Patches & Get_Failed_Patches
           
            //bool checkApplied, checkAvailable, checkFailed = false;
           
            //removes placeholder text on run
            if (Console.Text == "Console")
            {
                Console.Text = "";
            }

            foreach (string server in serverList)
            {
                string holdMe;

                //Pre-processing, check if server is online & converting to FQDN
                bool pingMe = false;
                pingMe = PingHost(server);
                string FQDN = server;
                FQDN = getFQDN(server, pingMe);

                // defining schedule IDs for client remediation
                System.Windows.Application.Current.Dispatcher.Invoke((Action)(() =>
                {
                    if (Software_Inventory.IsChecked == true)
                    {
                        if (pingMe == true)
                        {
                            Console.AppendText(FQDN + ": Software Inventory Cycle Started" + Environment.NewLine);
                            holdMe = "00000000-0000-0000-0000-000000000001";
                            TriggerSchedule(FQDN, holdMe);
                        }

                        else
                        {
                            Console.AppendText(FQDN + " is offline, can't run Software Inventory Cycle" + Environment.NewLine);
                        }

                    }
                }));
                if (Hardware_Inventory.IsChecked == true)
                {
                    if (pingMe == true)
                    {
                        Console.AppendText(FQDN + ": Hardware Inventory Cycle Started" + Environment.NewLine);
                        holdMe = "00000000-0000-0000-0000-000000000002";
                        TriggerSchedule(FQDN, holdMe);
                    }

                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't run Hardware Inventory Cycle" + Environment.NewLine);
                    }

                }
                if (Heartbeat.IsChecked == true)
                {
                    if (pingMe == true)
                    {
                        Console.AppendText(FQDN + ": Heartbeat Request Sent" + Environment.NewLine);
                        holdMe = "00000000-0000-0000-0000-000000000003";
                        TriggerSchedule(FQDN, holdMe);
                    }

                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't trigger Heartbeat" + Environment.NewLine);
                    }

                }

                if (Request_Machine_Policy.IsChecked == true)
                {
                    if (pingMe == true)
                    {
                        Console.AppendText(FQDN + ": Machine Policy Requested" + Environment.NewLine);
                        holdMe = "00000000-0000-0000-0000-000000000021";
                        TriggerSchedule(FQDN, holdMe);
                    }

                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't receive Machine Policy" + Environment.NewLine);
                    }

                }

                if (Force_Update_Scan.IsChecked == true)
                {
                    if (pingMe == true)
                    {
                        Console.AppendText(FQDN + ": Force Update Scan Task Triggered" + Environment.NewLine);
                        holdMe = "00000000-0000-0000-0000-000000000113";
                        TriggerSchedule(FQDN, holdMe);
                    }

                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't Force Update Scan" + Environment.NewLine);
                    }

                }

                if (Refresh_Location_Services.IsChecked == true)
                {
                    if (pingMe == true)
                    {
                        Console.AppendText(FQDN + ": Refresh Location Services Task Triggered" + Environment.NewLine);
                        holdMe = "00000000-0000-0000-0000-000000000024";
                        TriggerSchedule(FQDN, holdMe);
                    }

                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't Refresh Location Services" + Environment.NewLine);
                    }

                }

                if (Evaluate_Machine_Policy_Assignments.IsChecked == true)
                {
                    if (pingMe == true)
                    {
                        Console.AppendText(FQDN + ": Evaluate Machine Policy Assignments Task Triggered" + Environment.NewLine);
                        holdMe = "00000000-0000-0000-0000-000000000022";
                        TriggerSchedule(FQDN, holdMe);
                    }

                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't Evaluate Machine Policy Assignments" + Environment.NewLine);
                    }

                }

                if (Ping_Status.IsChecked == true)
                {
                    //pings systems in list
                    if (pingMe)
                    {
                        Console.AppendText(FQDN + " is online" + Environment.NewLine); 
                    }
                    else
                    {
                        Console.AppendText(FQDN + " is offline" + Environment.NewLine);
                    }
                }

                if (Reboot_Status.IsChecked == true)
                {
                    //checks systems in list for pending reboot due to SCCM
                    if(pingMe == true)
                    {
                        checkReboot(FQDN);
                    }
                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't check pending reboot status" + Environment.NewLine);
                    }
                    
                }

                if (Check_SCCM_Site.IsChecked == true)
                {
                    //verifies what SCCM site the client is pointed at
                    if(pingMe == true)
                    {
                        checkSite(FQDN);
                    }
                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't check assigned Site" + Environment.NewLine);
                    }
                    
                }

                if (Check_DNS_Status.IsChecked == true)
                {
                    //verify if there is a DNS issue.  This wouldn't be necessary if we turned on reverse DNS scavenging...
                    if(pingMe == true)
                    {
                        checkDNS(FQDN);
                    }
                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't check DNS status" + Environment.NewLine);
                    }
                    
                }
                
                if(Get_Available_Patches.IsChecked == true)
                {
                    //checks system for patches that are available but not applied
                    if (pingMe == true)
                    {
                        using (new WaitCursor())
                        {
                            Console.AppendText("Available patches for " + server + ":" + Environment.NewLine);
                            checkPatches(FQDN, 0);
                        }
                        Console.AppendText(server + " End of available patches" + Environment.NewLine);
                    }
                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't check for available patches" + Environment.NewLine);
                    }

                }

                if(Get_Failed_Patches.IsChecked == true)
                {
                    if (pingMe == true)
                    {   
                        using (new WaitCursor())
                        {
                            //checks system for failed patches
                            Console.AppendText("Failed patches for " + server + ":" + Environment.NewLine);
                            checkPatches(FQDN, 13);
                        }
                        Console.AppendText(server + " End of failed patches" + Environment.NewLine);
                    }
                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't check for failed patches" + Environment.NewLine);
                    }
                }
                
                if(Apply_Available_Patches.IsChecked == true) 
                {
                    //applies ALL AVAILABLE patches to system
                    //DialogResult warning = System.Windows.Forms.MessageBox.Show("DO YOU WANT TO APPLY ALL AVAILABLE PATCHES TO THE " + serverList.Count().ToString() + " SYSTEMS IN THE LIST?", "WARNING", MessageBoxButtons.YesNo);
                  
                    await Task.Run(() =>
                    {
                        patchEverything(FQDN);
                    });
                }
                
                /*if(Reboot_All_Servers.IsChecked == true)
                {
                    //reboots ALL SYSTEMS in computerlist.Text
                    DialogResult warning = System.Windows.Forms.MessageBox.Show("DO YOU WANT TO REBOOT ALL " + serverList.Count().ToString() + " SYSTEMS IN THE LIST?", "WARNING", MessageBoxButtons.YesNo);
                    if (warning == System.Windows.Forms.DialogResult.Yes)
                    {
                        rebootSystem(FQDN);
                    }
                }
                */
                
                if (Get_Applied_Patches.IsChecked == true)
                {
                    //converts # in days.Text to int then get the applied patches daysConv in the past
                    int daysConv = Int32.Parse(days.Text);
                    if (pingMe == true)
                    {
                        string domain = getDomain(server, 1);
                        /*
                        if (domain == "***DEV***")
                        {
                            Console.AppendText(domain + " is not supported yet for getAppliedPatches(FQDN, daysConv)" + Environment.NewLine);
                        }
                        
                        else
                        {*/
            using (new WaitCursor())
                            {
                                getAppliedPatches(FQDN, daysConv);
                            }
                        //}
                    }
                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't retrieve past " + daysConv + " days of patches" + Environment.NewLine);
                    }
                    
                }
                
                if(Get_FQDN.IsChecked == true)
                {
                    if(pingMe == true)
                    {
                        Console.AppendText(FQDN + Environment.NewLine);
                    }
                    else
                    {
                        Console.AppendText(FQDN + " is offline, can't check FQDN" + Environment.NewLine);
                    }
                    
                }

                if(check_uptime.IsChecked == true)
                {
                    using (new WaitCursor())
                    {
                        //for some reason, I can't access the Console.AppendText inside the GetUptime method - so I'm just going to do it from here.
                        string getSystemUptime = GetUptime(FQDN).ToString(@"dd\.hh\:mm\:ss");
                        Console.AppendText(server + " Uptime: " + getSystemUptime + Environment.NewLine);
                    }
                    
                }
            }
        }

        private void Get_Failed_Patches_Checked(object sender, RoutedEventArgs e)
        {

        }
    }
}
