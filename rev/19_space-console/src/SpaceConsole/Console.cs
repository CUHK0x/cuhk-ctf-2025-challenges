using System.Security.Cryptography;

namespace SpaceConsole;

class SpaceConsole
{
    struct SpaceshipState
    {
        public SpaceshipState() { }
        public enum Checks
        {
            System,
            GroundStatus,
            Comms,
            GroundLaunchAuth,
        }
        public List<Checks> performedChecks = [];
        public bool sys = false;
        public bool gs = false;
        public bool comms = false;
        public bool gl_auth = false;
        public bool launch = false;
        public bool countdown = false;
        public TaskCompletionSource countdownTask = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int booster_detached = 0;
        public int alt = 0;
        public string? launchAbortReason;
        // Use a state to restrict command calls, but not its parameters
        public enum LaunchStage
        {
            NONE,
            PRE120,
            PRE60,
            PRE15,
            LAUNCHED,
        }
        public LaunchStage launchStage = LaunchStage.NONE;
    }
    private SpaceshipState state = new();
    private readonly object stateLock = new object();
    private string allIO = ""; // a permutation that is used to generate the key for the flag
    private readonly Dictionary<string, Action<string[]>> commands;
    private class CallCount
    {
        public int Check = 0;
        public int Launch = 0;
        public int Countdown = 0;
        public int Detach = 0;
        public int Shutdown = 0;
    }
    private readonly CallCount callCount = new();
    private const string errBc = "Bad Command!";
    private const string errTooMany = "You can't do that that many times!";
    private const string errOutOfSeq = "You did not follow the procedure correctly!";
    private void OutLine(string line)
    {
        allIO += line + "\n";
        Console.WriteLine(line);
    }
    public void Check(string[] param)
    {
        if (callCount.Check++ > 3) Abort(errTooMany);
        var args_str = string.Join(' ', param);
        if (args_str == "system")
        {
            OutLine("Thrusters ready.\nInertial navigation systems normal.\nHydraulic systems normal.");
            state.sys = true;
            state.performedChecks.Add(SpaceshipState.Checks.System);
        }
        else if (args_str == "ground status")
        {
            OutLine("Ground status normal.");
            state.gs = true;
            state.performedChecks.Add(SpaceshipState.Checks.GroundStatus);
        }
        else if (args_str == "comms")
        {
            OutLine("Comms Check OK.");
            state.comms = true;
            state.performedChecks.Add(SpaceshipState.Checks.Comms);
        }
        else if (args_str == "ground launch auth")
        {
            OutLine("Launch authority granted.");
            state.gl_auth = true;
            state.performedChecks.Add(SpaceshipState.Checks.GroundLaunchAuth);
        }
        else
        {
            Abort(errBc);
        }
    }
    public void Launch(string[] param)
    {
        if (callCount.Launch++ > 0) Abort(errTooMany);
        if (state.launchAbortReason is not null)
        {
            Abort(state.launchAbortReason);
        }
        if (param.Length > 0)
        {
            Abort(errBc);
        }
        if (!state.comms)
        {
            Abort("You did not check the communications system!");
        }
        if (!state.sys)
        {
            Abort("You did not check the spaceship system!");
        }
        if (!state.gl_auth)
        {
            Abort("You did not check ground authority!");
        }
        if (!state.gs)
        {
            Abort("You did not check ground control status!");
        }
        if (!state.performedChecks.SequenceEqual([
            SpaceshipState.Checks.System,
            SpaceshipState.Checks.GroundStatus,
            SpaceshipState.Checks.Comms,
            SpaceshipState.Checks.GroundLaunchAuth,
            ]))
        {
            Abort(errOutOfSeq);
        }
        state.launch = true;
        OutLine("Launch Confirmed.");
    }
    public void Countdown(string[] param)
    {
        if (callCount.Countdown++ > 0) Abort(errTooMany);
        state.countdown = true;
        for (int i = 10; i > 0; i--)
        {
            ExpectLine(i.ToString(), "Astronaut that cannot count cannot into space. Aborting...");
        }
        state.countdownTask.SetResult();
    }
    public void Detach(string[] param)
    {
        if (callCount.Detach++ > 1) Abort(errTooMany);
        if (param.Length != 3) Abort(errBc);
        if (param[0] == "booster")
        {
            if (param[1] != "stage")
            {
                Abort("Choose booster stage!");
            }
        }
        else Abort($"Detaching {param[0]} is not supported!");
        var parseSuccess = int.TryParse(param[2], out var x);
        if (!parseSuccess) Abort("Stage must be a number!");
        var stages = new Dictionary<int, int> { { 1, 100 }, { 2, 300 } }; // stage number, alt
        var accept = stages.TryGetValue(x, out var target_alt);
        if (!accept) Abort($"No stage {x} booster!");
        if (state.alt != target_alt) Abort("Wrong timing!");
        state.booster_detached = x;
    }
    public void Shutdown(string[] param)
    {
        if (callCount.Shutdown++ > 0) Abort(errTooMany);
        if (!param.SequenceEqual(["thrusters"])) Abort(errBc);
        state.booster_detached = 3;
        // Since shutdown is the last command in async terminal input mode, we'll just stop the terminal thread here
    }
    private bool ExecLine(string line)
    {
        var words = line.Split(' ');
        if (words.Length < 1 || !commands.TryGetValue(words[0], out var f))
        {
            Abort($"Unrecognized command: {line}");
            return false; // unreachable, but here to keep compiler happy
        }
        switch (state.launchStage)
        {
            case SpaceshipState.LaunchStage.NONE:
                Abort("Spaceship is not ready!");
                break;
            case SpaceshipState.LaunchStage.PRE120:
                if (f != Check) Abort(errBc);
                break;
            case SpaceshipState.LaunchStage.PRE60:
                if (f != Check && f != Launch) Abort(errBc);
                break;
            case SpaceshipState.LaunchStage.PRE15:
                if (f != Countdown) Abort(errBc);
                break;
            case SpaceshipState.LaunchStage.LAUNCHED:
                if (f != Detach && f != Shutdown) Abort(errBc);
                break;
        }
        f([.. words.Skip(1).Take(words.Length - 1)]);
        return true;
    }
    private void ExpectLine(string expected, string errMsg = errBc)
    {
        var line = Console.ReadLine();
        allIO += line + '\n';
        if (line != expected) Abort(errMsg);
    }
    private static void Abort(string reason)
    {
        Console.WriteLine(reason);
        Console.WriteLine("Mission failed. Better luck next time.");
        Environment.Exit(1);
    }
    private void Conversation((string[], string[])[] conv)
    {
        foreach (var (q, a) in conv)
        {
            foreach (var l in q)
            {
                OutLine($"Ground: {l}");
            }
            ExpectLine("COMM");
            foreach (var l in a)
            {
                ExpectLine(l);
            }
            ExpectLine("OUT");
        }
    }
    private void Chatters()
    {
        Conversation([
            (["Status number 1"], ["Uhhh we're proceeding the target, over."]),
            (["Number 3, anything?"], ["No, negative, nothing."]),
            (["Rodger that.", "Hey, what's your status?"], ["We're on course, on time and on target. Everything's fine, how are you?"]),
        ]);
        for (int i = 0; i < 3; i++)
        {
            Console.Write('.');
            Thread.Sleep(1000);
        }
        Console.WriteLine();
        Conversation([
            (["This is Ground Control to Major Tom", "You've really made the grade", "And the papers want to know whose shirts you wear", "Now it's time to leave the capsule if you dare"], ["This is Major Tom to Ground Control", "I'm stepping through the door", "And I'm floating in a most peculiar way", "And the stars look very different today", "For here"]),
            (["Ground Control to Major Tom", "Your circuit's dead, there's something wrong", "Can you hear me, Major Tom?", "Can you hear me, Major Tom?", "Can you hear me, Major Tom? Can you-"], ["Here am I floating 'round my tin can", "Far above the moon", "Planet Earth is blue", "And there's nothing I can do"])
        ]);
    }
    public async Task<string> GoToSpace()
    {
        var cancelTokenSource = new CancellationTokenSource();
        var terminalTask = Terminal(cancelTokenSource.Token); // should probably wait for this task to start running, idk

        Monitor.Enter(stateLock);

        OutLine("T=-120s");
        state.launchStage = SpaceshipState.LaunchStage.PRE120;
        // TODO: Change back to 60s

        Monitor.Exit(stateLock);
        Thread.Sleep(15000); // 60s
        Monitor.Enter(stateLock);

        List<SpaceshipState.Checks> expectedChecks = [SpaceshipState.Checks.System, SpaceshipState.Checks.GroundStatus];
        // Exactly "system" then "ground status" check should be performed
        if (!state.performedChecks.SequenceEqual(expectedChecks))
        {
            state.launchAbortReason = errOutOfSeq;
        }
        OutLine("T=-60s");
        state.launchStage = SpaceshipState.LaunchStage.PRE60;

        Monitor.Exit(stateLock);
        Thread.Sleep(15000); // 45s
        Monitor.Enter(stateLock);

        if (!state.launch)
        {
            Abort("No launch confirmation before T=-15s, aborting mission.");
        }
        OutLine("T=-15s");
        state.launchStage = SpaceshipState.LaunchStage.PRE15;

        Monitor.Exit(stateLock);
        Thread.Sleep(5000);
        Monitor.Enter(stateLock);

        if (!state.countdown)
        {
            Abort("Commence countdown before T=-10s!");
        }
        // wait for the countdown to end, countdown is blocking
        await state.countdownTask.Task;
        OutLine("Booster ignited.");
        state.launchStage = SpaceshipState.LaunchStage.LAUNCHED;
        var nums = new int[] { 1, 5, 10, 20, 50, 100, 150, 200, 300, 325, 340 };
        string? failReason = null;
        foreach (var num in nums)
        {
            Monitor.Exit(stateLock);
            Thread.Sleep(5000); // TODO: Was 3000ms
            Monitor.Enter(stateLock);

            state.alt = num;
            // enforce that detaching can only happen in 100km~150km and 300km~325km in DETACH command
            // set fail only if the play had not already failed.
            if (num == 150 && state.booster_detached != 1 && failReason is null) failReason = "You did not detach stage 1 booster!";
            if (num == 325 && state.booster_detached != 2 && failReason is null) failReason = "You did not detach stage 2 booster!";
            if (num == 340 && state.booster_detached != 3 && failReason is null) failReason = "You did not stop the thruster!";
            OutLine($"{num}km");
        }
        if (failReason is not null) Abort(failReason);
        // Expect the last input is SHUTDOWN command, if it is not, this thread will kill the process.
        Monitor.Exit(stateLock);
        await terminalTask;
        // Transition to synchronous reading
        OutLine("Approaching orbit altitude...");
        // Expect thread created from Terminal() to stop here, and we can start synchronously reading from stdin again.
        ExpectLine("ORBIT");
        OutLine("Switching to orbit mode...");
        Thread.Sleep(2000);
        OutLine("In orbital speed.");
        ExpectLine("DOCK iss");
        OutLine("Docking...");
        Thread.Sleep(3000);
        OutLine("Docked to ISS.");
        Chatters();
        OutLine("FS: At least you got the flag.");
        ExpectLine("FLAG");
        // Decrypt the flag from ciphertext here
        return allIO;
    }
    public Task Terminal(CancellationToken ct)
    {
        return Task.Run(() =>
        {
            /**
             * Exception thrown: 'System.InvalidOperationException' in System.Console.dll:
             * 'Cannot see if a key has been pressed when either application does not have a console
             * or when console input has been redirected from a file. Try Console.In.Peek.'
             */
            // Console.KeyAvailable may throw if not run in a console, but does not necessarily crashes
            // the program.
            // while (Console.KeyAvailable)
            //     Console.ReadKey(false); // skips previous input charsConsole.Clear
            while (!ct.IsCancellationRequested && state.booster_detached != 3)
            {
                Console.Write("> ");
                var line = Console.ReadLine();
                lock (stateLock)
                {
                    if (line is null) Abort("Console Error");
                    allIO += line + '\n';
                    ExecLine(line!);
                }
            }
        }, ct);
    }
    public SpaceConsole()
    {
        commands = new Dictionary<string, Action<string[]>>
        {
            {"CHECK", Check},
            {"LAUNCH", Launch},
            {"COUNTDOWN", Countdown},
            {"DETACH", Detach},
            {"SHUTDOWN", Shutdown},
        };
    }
}
