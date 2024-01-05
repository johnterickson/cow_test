using Microsoft.CopyOnWrite;

public class Program
{
    public static int Main(string[] args)
    {
        // Create a new instance of the CopyOnWriteFilesystem class
        ICopyOnWriteFilesystem cow = CopyOnWriteFilesystemFactory.GetInstance();

        string from = args[0];
        string to = args[1];

        

        bool cowFrom = cow.CopyOnWriteLinkSupportedInDirectoryTree(Path.GetDirectoryName(from)!);
        bool cowTo = cow.CopyOnWriteLinkSupportedInDirectoryTree(Path.GetDirectoryName(to)!);
        bool cowBetween = cow.CopyOnWriteLinkSupportedBetweenPaths(from, to);

        Console.WriteLine($"CopyOnWrite supported in {from}: {cowFrom}");
        Console.WriteLine($"CopyOnWrite supported in {to}: {cowTo}");
        Console.WriteLine($"CopyOnWrite supported between {from} and {to}: {cowBetween}");

        if (!cowBetween)
        {
            return 1;
        }

        cow.CloneFile(from, to);
        Console.WriteLine($"Cloned {from} to {to}");

        return 0;
    }
}