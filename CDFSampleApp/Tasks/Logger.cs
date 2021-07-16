using System.IO;
using System.Diagnostics;
using System.Runtime.CompilerServices;


namespace Tasks {
    internal class Logger {
        private const string Path = @"C:\temp\log.txt";

        internal void Log(string message, [CallerMemberName] string member = null)
        {
            //if (!File.Exists(Path)) {
            //    File.Create(Path);
            //}

            //File.AppendAllText(Path, $"{message}\r\n");

            // EventLog.WriteEntry(member, message, EventLogEntryType.Error);
        }
    }
}
