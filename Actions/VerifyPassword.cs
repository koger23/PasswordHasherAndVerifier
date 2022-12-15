using Microsoft.Xrm.Sdk;
using System;
using System.Security.Cryptography;

namespace kogerohu.Actions
{
    public class VerifyPassword : IPlugin
    {
        public void Execute(IServiceProvider serviceProvider)
        {
            IPluginExecutionContext executionContext = (IPluginExecutionContext)serviceProvider.GetService(typeof(IPluginExecutionContext));

            var password = (string)executionContext.InputParameters["password"];
            var passwordHash = (string)executionContext.InputParameters["passwordHash"];

            byte[] hashBytes = Convert.FromBase64String(passwordHash);
            byte[] salt = new byte[16];

            Array.Copy(hashBytes, 0, salt, 0, 16);

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000);
            byte[] hash = pbkdf2.GetBytes(20);
            bool isValid = false;

            for (int i = 0; i < 20; i++)
            {
                if (hashBytes[i + 16] != hash[i])
                {
                    executionContext.OutputParameters["isValid"] = isValid;
                    return;
                }
            }
            isValid = true;
            executionContext.OutputParameters["isValid"] = isValid;
        }
    }
}
