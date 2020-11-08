using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;

namespace DCEnumNC
{
    class EnumDC
    {

        public static string GetDCInfo()
        {
            string ret = "";

            try
            {
                var myDomain = Domain.GetComputerDomain();
                foreach (DomainController dc in myDomain.DomainControllers)
                {
                    ret = "DC name: " + dc.Name + ", IP: " + dc.IPAddress;
                }
            }
            catch (Exception ex)
            {
                ret = "An error has occured: " + ex.Message + Environment.NewLine + ex.StackTrace;
            }

            return ret;
        }
    }
}
