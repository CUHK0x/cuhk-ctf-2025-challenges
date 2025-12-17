using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SpaceConsole;

/**
 * Idiot tries async programming
 */
class Program
{
    static string ClaimFlag(string log)
    {
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(log));
        using var decryptor = Aes.Create();
        decryptor.Key = digest;
        var plainText = decryptor.DecryptCbc(
            Convert.FromHexString("673f44af7ee8c3312da196b348362b09ba249731eb359a404d7698f529aeabc423fba83f7fe65aa2ed9c9c856c3d704300f6c72eb2c083b8ff0b76aa4f0e25f59cc5f692843edbea1df519207e227fad174f4fb9da4d94e303c755e386d080aa"),
            Convert.FromHexString("12e104fe3aac082d1a67eee7971404fc")
        );
        var flag = Encoding.ASCII.GetString(plainText);
        if (!Regex.IsMatch(flag, @"^cuhk25ctf{.+}$"))
        {
            Console.Error.WriteLine("This should not happen. If you did not patch the program, please open a ticket, and send the following:");
            Console.Error.Write(log);
            Console.Error.Flush();
            Environment.Exit(1);
        }
        return flag;
    }
    static async Task Main(string[] args)
    {
        // Banner
        Console.WriteLine("""
        ====================================================================
           _____                          ______                       __   
          / ___/____  ____ _________     / ____/___  ____  _________  / /__ 
          \__ \/ __ \/ __ `/ ___/ _ \   / /   / __ \/ __ \/ ___/ __ \/ / _ \
         ___/ / /_/ / /_/ / /__/  __/  / /___/ /_/ / / / (__  ) /_/ / /  __/
        /____/ .___/\__,_/\___/\___/   \____/\____/_/ /_/____/\____/_/\___/ 
            /_/                                                             
        ====================================================================
        """);
        if (!args.SequenceEqual(["Major Tom"]))
        {
            Console.WriteLine("Unauthorized.");
            Environment.Exit(1);
        }
        Console.WriteLine($"Hello, {args[0]}!");
        SpaceConsole spaceConsole = new();
        var log = await spaceConsole.GoToSpace();
        Console.WriteLine($"Thanks for playing! Here is your flag: {ClaimFlag(log)}");
    }
}
