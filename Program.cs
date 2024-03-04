using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using BuildXL.Native.IO;
using Microsoft.CopyOnWrite;
using Microsoft.Win32.SafeHandles;

public class Program
{
    public static int Main(string[] args)
    {
        // Create a new instance of the CopyOnWriteFilesystem class
        ICopyOnWriteFilesystem cow = CopyOnWriteFilesystemFactory.GetInstance();

        string workingDir = Environment.CurrentDirectory;
        OpenFileResult directoryOpenResult = TryOpenDirectory(
            workingDir,
            FileShare.ReadWrite | FileShare.Delete,
            out SafeFileHandle directoryHandle);

        Console.WriteLine($"Is ReFS? {GetVolumeFileSystemByHandle(directoryHandle)}");


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

    public static FileSystemType GetVolumeFileSystemByHandle(SafeFileHandle fileHandle)
    {
        var fileSystemNameBuffer = new StringBuilder(32);
        bool success = GetVolumeInformationByHandleW(
            fileHandle,
            volumeNameBuffer: null,
            volumeNameBufferSize: 0,
            volumeSerial: IntPtr.Zero,
            maximumComponentLength: IntPtr.Zero,
            fileSystemFlags: IntPtr.Zero,
            fileSystemNameBuffer: fileSystemNameBuffer,
            fileSystemNameBufferSize: fileSystemNameBuffer.Capacity);
        if (!success)
        {
            int hr = Marshal.GetLastWin32Error();
            throw ThrowForNativeFailure(hr, "GetVolumeInformationByHandleW");
        }

        string fileSystemName = fileSystemNameBuffer.ToString();
        switch (fileSystemName)
        {
            case "NTFS":
                return FileSystemType.NTFS;
            case "ReFS":
                return FileSystemType.ReFS;
            default:
                return FileSystemType.Unknown;
        }
    }

    
    public static OpenFileResult TryOpenDirectory(string directoryPath, FileShare shareMode, out SafeFileHandle handle)
    {
        // Contract.Requires(!string.IsNullOrEmpty(directoryPath));

        return TryOpenDirectory(directoryPath, FileDesiredAccess.None, shareMode, FileFlagsAndAttributes.None, out handle);
    }

    public static OpenFileResult TryOpenDirectory(
        string directoryPath,
        FileDesiredAccess desiredAccess,
        FileShare shareMode,
        FileFlagsAndAttributes flagsAndAttributes,
        out SafeFileHandle? handle)
    {
        return TryOpenDirectory(directoryPath, desiredAccess, shareMode, FileMode.Open, flagsAndAttributes, out handle);
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(
        SafeFileHandle fileHandle,
        [Out] StringBuilder? volumeNameBuffer, // Buffer for volume name (if not null)
        int volumeNameBufferSize,
        IntPtr volumeSerial, // Optional pointer to a DWORD to be populated with the volume serial number
        IntPtr maximumComponentLength, // Optional pointer to a DWORD to be populated with the max component length.
        IntPtr fileSystemFlags, // Optional pointer to a DWORD to be populated with flags of supported features on the volume (e.g. hardlinks)
        [Out] StringBuilder fileSystemNameBuffer, // Buffer for volume FS, e.g. "NTFS" (if not null)
        int fileSystemNameBufferSize);


    internal static Exception ThrowForNativeFailure(int error, string nativeApiName, [CallerMemberName] string managedApiName = "<unknown>")
    {
        throw CreateWin32Exception(error, nativeApiName, managedApiName);
    }

    internal static Win32Exception CreateWin32Exception(int error, string nativeApiName, [CallerMemberName] string managedApiName = "<unknown>")
    {
        return new Win32Exception(error, $"{nativeApiName} for {managedApiName} failed");
    }

    public enum FileSystemType
    {
        #pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        NTFS,
        ReFS,
        APFS,
        HFS,
        EXT3,
        EXT4,
        Unknown,
        #pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    static OpenFileResult TryOpenDirectory(
        string directoryPath,
        FileDesiredAccess desiredAccess,
        FileShare shareMode,
        FileMode fileMode,
        FileFlagsAndAttributes flagsAndAttributes,
        out SafeFileHandle? handle)
    {
        // Contract.Requires(!string.IsNullOrEmpty(directoryPath));

        handle = CreateFileW(
            directoryPath, //ToLongPathIfExceedMaxPath(directoryPath),
            desiredAccess | FileDesiredAccess.Synchronize,
            shareMode,
            lpSecurityAttributes: IntPtr.Zero,
            dwCreationDisposition: fileMode,
            dwFlagsAndAttributes: flagsAndAttributes | FileFlagsAndAttributes.FileFlagBackupSemantics,
            hTemplateFile: IntPtr.Zero);
        int hr = Marshal.GetLastWin32Error();

        if (handle.IsInvalid)
        {
            // Logger.Log.StorageTryOpenDirectoryFailure(m_loggingContext, directoryPath, hr);
            handle = null;
            // Contract.Assert(hr != 0);
            var result = OpenFileResult.Create(directoryPath, hr, fileMode, handleIsValid: false);
            // Contract.Assert(!result.Succeeded);
            return result;
        }
        else
        {
            var result = OpenFileResult.Create(directoryPath, hr, fileMode, handleIsValid: true);
            // Contract.Assert(result.Succeeded);
            return result;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        FileDesiredAccess dwDesiredAccess,
        FileShare dwShareMode,
        IntPtr lpSecurityAttributes,
        FileMode dwCreationDisposition,
        FileFlagsAndAttributes dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    /// <summary>
    /// Desired access flags for <see cref="Windows.FileSystemWin.CreateFileW"/>
    /// </summary>
    [Flags]
    public enum FileDesiredAccess : uint
    {
        /// <summary>
        /// No access requested.
        /// </summary>
        None = 0,

        /// <summary>
        /// Waitable handle (always required by CreateFile?)
        /// </summary>
        Synchronize = 0x00100000,

        /// <summary>
        /// Object can be deleted.
        /// </summary>
        Delete = 0x00010000,

        /// <summary>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/aa364399(v=vs.85).aspx
        /// </summary>
        GenericRead = 0x80000000,

        /// <summary>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/aa364399(v=vs.85).aspx
        /// </summary>
        GenericWrite = 0x40000000,

        /// <summary>
        /// Can read file or directory attributes.
        /// </summary>
        FileReadAttributes = 0x0080,

        /// <summary>
        /// The right to write file attributes.
        /// </summary>
        FileWriteAttributes = 0x00100,
    }

    /// <summary>
    /// Flags for <c>CreateFile</c> and <c>OpenFileById</c>
    /// </summary>
    [Flags]
    public enum FileFlagsAndAttributes : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,

        /// <summary>
        /// The file should be archived. Applications use this attribute to mark files for backup or removal.
        /// </summary>
        FileAttributeArchive = 0x20,

        /// <summary>
        /// The file or directory is encrypted. For a file, this means that all data in the file is encrypted. For a directory,
        /// this means that encryption is the default for newly created files and subdirectories. For more information, see File
        /// Encryption.
        /// This flag has no effect if FILE_ATTRIBUTE_SYSTEM is also specified.
        /// </summary>
        FileAttributeEncrypted = 0x4000,

        /// <summary>
        /// The file is hidden. Do not include it in an ordinary directory listing.
        /// </summary>
        FileAttributeHidden = 0x2,

        /// <summary>
        /// The file does not have other attributes set. This attribute is valid only if used alone.
        /// </summary>
        FileAttributeNormal = 0x80,

        /// <summary>
        /// The data of a file is not immediately available. This attribute indicates that file data is physically moved to offline
        /// storage. This attribute is used by Remote Storage, the hierarchical storage management software. Applications should
        /// not arbitrarily change this attribute.
        /// </summary>
        FileAttributeOffline = 0x1000,

        /// <summary>
        /// The file is read only. Applications can read the file, but cannot write to or delete it.
        /// </summary>
        FileAttributeReadOnly = 0x1,

        /// <summary>
        /// The file is part of or used exclusively by an operating system.
        /// </summary>
        FileAttributeSystem = 0x4,

        /// <summary>
        /// The file is being used for temporary storage.
        /// </summary>
        FileAttributeTemporary = 0x100,

        /// <summary>
        /// The file is being opened or created for a backup or restore operation. The system ensures that the calling process
        /// overrides file security checks when the process has SE_BACKUP_NAME and SE_RESTORE_NAME privileges. For more
        /// information, see Changing Privileges in a Token.
        /// You must set this flag to obtain a handle to a directory. A directory handle can be passed to some functions instead of
        /// a file handle.
        /// </summary>
        FileFlagBackupSemantics = 0x02000000,

        /// <summary>
        /// The file is to be deleted immediately after all of its handles are closed, which includes the specified handle and any
        /// other open or duplicated handles.
        /// If there are existing open handles to a file, the call fails unless they were all opened with the FILE_SHARE_DELETE
        /// share mode.
        /// Subsequent open requests for the file fail, unless the FILE_SHARE_DELETE share mode is specified.
        /// </summary>
        FileFlagDeleteOnClose = 0x04000000,

        /// <summary>
        /// The file or device is being opened with no system caching for data reads and writes. This flag does not affect hard
        /// disk caching or memory mapped files.
        /// </summary>
        FileFlagNoBuffering = 0x20000000,

        /// <summary>
        /// The file data is requested, but it should continue to be located in remote storage. It should not be transported back
        /// to local storage. This flag is for use by remote storage systems.
        /// </summary>
        FileFlagOpenNoRecall = 0x00100000,

        /// <summary>
        /// Normal reparse point processing will not occur; CreateFile will attempt to open the reparse point. When a file is
        /// opened, a file handle is returned, whether or not the filter that controls the reparse point is operational.
        /// This flag cannot be used with the CREATE_ALWAYS flag.
        /// If the file is not a reparse point, then this flag is ignored.
        /// </summary>
        FileFlagOpenReparsePoint = 0x00200000,

        /// <summary>
        /// The file or device is being opened or created for asynchronous I/O.
        /// When subsequent I/O operations are completed on this handle, the event specified in the OVERLAPPED structure will be
        /// set to the signaled state.
        /// If this flag is specified, the file can be used for simultaneous read and write operations.
        /// If this flag is not specified, then I/O operations are serialized, even if the calls to the read and write functions
        /// specify an OVERLAPPED structure.
        /// </summary>
        FileFlagOverlapped = 0x40000000,

        /// <summary>
        /// Access will occur according to POSIX rules. This includes allowing multiple files with names, differing only in case,
        /// for file systems that support that naming.
        /// Use care when using this option, because files created with this flag may not be accessible by applications that are
        /// written for MS-DOS or 16-bit Windows.
        /// </summary>
        FileFlagPosixSemantics = 0x01000000,

        /// <summary>
        /// Access is intended to be random. The system can use this as a hint to optimize file caching.
        /// This flag has no effect if the file system does not support cached I/O and FILE_FLAG_NO_BUFFERING.
        /// </summary>
        FileFlagRandomAccess = 0x10000000,

        /// <summary>
        /// The file or device is being opened with session awareness. If this flag is not specified, then per-session devices
        /// (such as a redirected USB device) cannot be opened by processes running in session 0.
        /// </summary>
        FileFlagSessionAware = 0x00800000,

        /// <summary>
        /// Access is intended to be sequential from beginning to end. The system can use this as a hint to optimize file caching.
        /// This flag should not be used if read-behind (that is, reverse scans) will be used.
        /// This flag has no effect if the file system does not support cached I/O and FILE_FLAG_NO_BUFFERING.
        /// For more information, see the Caching Behavior section of this topic.
        /// </summary>
        FileFlagSequentialScan = 0x08000000,

        /// <summary>
        /// Write operations will not go through any intermediate cache, they will go directly to disk.
        /// </summary>
        FileFlagWriteThrough = 0x80000000,

        /// <summary>
        /// When opening a named pipe, the pipe server can only impersonate this client at the 'anonymous' level (i.e., no privilege is made available).
        /// </summary>
        /// <remarks>
        /// This is actually <c>SECURITY_SQOS_PRESENT</c> which makes <c>CreateFile</c> respect SQQS flags; those flags are ignored unless this is specified.
        /// But <c>SECURITY_ANONYMOUS</c> is zero; so think of this as those two flags together (much easier to use correctly).
        ///
        /// Please also note that SECURITY_SQOS_PRESENT is the same value as FILE_FLAG_OPEN_NO_RECALL.
        /// See the comment here for example: https://github.com/rust-lang/rust/blob/master/library/std/src/sys/windows/ext/fs.rs
        /// </remarks>
        SecurityAnonymous = 0x00100000,
    }

    /// <summary>
    /// Represents the result of attempting to open a file (such as with <see cref="IFileSystem.TryCreateOrOpenFile(string, FileDesiredAccess, System.IO.FileShare, System.IO.FileMode, FileFlagsAndAttributes, out Microsoft.Win32.SafeHandles.SafeFileHandle)"/>).
    /// </summary>
    public readonly struct OpenFileResult : IEquatable<OpenFileResult>
    {
        /// <summary>
        /// Native error code.
        /// </summary>
        /// <remarks>
        /// This is the same as returned by <c>GetLastError</c>, except when it is not guaranteed to be set; then it is normalized to
        /// <c>ERROR_SUCCESS</c>
        /// </remarks>
        public int NativeErrorCode { get; }

        /// <summary>
        /// Normalized status indication (derived from <see cref="NativeErrorCode"/> and the creation disposition).
        /// </summary>
        /// <remarks>
        /// This is useful for two reasons: it is an enum for which we can know all cases are handled, and successful opens
        /// are always <see cref="OpenFileStatus.Success"/> (the distinction between opening / creating files is moved to
        /// <see cref="OpenedOrTruncatedExistingFile"/>)
        /// </remarks>
        public OpenFileStatus Status { get; }

        /// <summary>
        /// Indicates if an existing file was opened (or truncated). For creation dispositions such as <see cref="System.IO.FileMode.OpenOrCreate"/>,
        /// either value is possible on success. On failure, this is always <c>false</c> since no file was opened.
        /// </summary>
        public bool OpenedOrTruncatedExistingFile { get; }

        /// <summary>
        /// The path of the file that was opened. Null if the path was opened by <see cref="FileId"/>.
        /// </summary>
        public string Path { get; }

        /// <summary>
        /// Creates an <see cref="OpenFileResult"/> without any normalization from native error code.
        /// </summary>
        private OpenFileResult(string path, OpenFileStatus status, int nativeErrorCode, bool openedOrTruncatedExistingFile)
        {
            Path = path;
            Status = status;
            NativeErrorCode = nativeErrorCode;
            OpenedOrTruncatedExistingFile = openedOrTruncatedExistingFile;
        }

        /// <summary>
        /// Creates an <see cref="OpenFileResult"/> from observed return values from a native function.
        /// Used when opening files by <see cref="FileId"/> to handle quirky error codes.
        /// </summary>
        public static OpenFileResult CreateForOpeningById(int nativeErrorCode, FileMode creationDisposition, bool handleIsValid)
        {
            return Create(path: null, nativeErrorCode, creationDisposition, handleIsValid, openingById: true);
        }

        /// <summary>
        /// Creates an <see cref="OpenFileResult"/> from observed return values from a native function.
        /// </summary>
        public static OpenFileResult Create(string path, int nativeErrorCode, FileMode creationDisposition, bool handleIsValid)
        {
            return Create(path, nativeErrorCode, creationDisposition, handleIsValid, openingById: false);
        }

        /// <summary>
        /// Creates an <see cref="OpenFileResult"/> from observed return values from a native function.
        /// </summary>
        /// <remarks>
        /// <paramref name="openingById"/> is needed since <c>OpenFileById</c> has some quirky error codes.
        /// </remarks>
        private static OpenFileResult Create(string? path, int nativeErrorCode, FileMode creationDisposition, bool handleIsValid, bool openingById)
        {
            // Here's a handy table of various FileModes, corresponding dwCreationDisposition, and their properties:
            // See http://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
            // Managed FileMode | Creation disp.    | Error always set? | Distinguish existence?    | Existing file on success?
            // ----------------------------------------------------------------------------------------------------------------
            // Append           | OPEN_ALWAYS       | 1                 | 1                         | 0
            // Create           | CREATE_ALWAYS     | 1                 | 1                         | 0
            // CreateNew        | CREATE_NEW        | 0                 | 0                         | 0
            // Open             | OPEN_EXISTING     | 0                 | 0                         | 1
            // OpenOrCreate     | OPEN_ALWAYS       | 1                 | 1                         | 0
            // Truncate         | TRUNCATE_EXISTING | 0                 | 0                         | 1
            //
            // Note that some modes always set a valid last-error, and those are the same modes
            // that distinguish existence on success (i.e., did we just create a new file or did we open one).
            // The others do not promise to set ERROR_SUCCESS and instead failure implies existence
            // (or absence) according to the 'Existing file on success?' column.
            bool modeDistinguishesExistence =
                creationDisposition == FileMode.OpenOrCreate ||
                creationDisposition == FileMode.Create ||
                creationDisposition == FileMode.Append;

            if (handleIsValid && !modeDistinguishesExistence)
            {
                nativeErrorCode = NativeIOConstants.ErrorSuccess;
            }

            OpenFileStatus status;
            var openedOrTruncatedExistingFile = false;

            switch (nativeErrorCode)
            {
                case NativeIOConstants.ErrorSuccess:
                    // Contract.Assume(handleIsValid);
                    status = OpenFileStatus.Success;
                    openedOrTruncatedExistingFile = creationDisposition == FileMode.Open || creationDisposition == FileMode.Truncate;
                    break;
                case NativeIOConstants.ErrorFileNotFound:
                    // Contract.Assume(!handleIsValid);
                    status = OpenFileStatus.FileNotFound;
                    break;
                case NativeIOConstants.ErrorPathNotFound:
                    // Contract.Assume(!handleIsValid);
                    status = OpenFileStatus.PathNotFound;
                    break;
                case NativeIOConstants.ErrorAccessDenied:
                    // Contract.Assume(!handleIsValid);
                    status = OpenFileStatus.AccessDenied;
                    break;
                case NativeIOConstants.ErrorSharingViolation:
                    // Contract.Assume(!handleIsValid);
                    status = OpenFileStatus.SharingViolation;
                    break;
                case NativeIOConstants.ErrorLockViolation:
                    // Contract.Assume(!handleIsValid);
                    status = OpenFileStatus.LockViolation;
                    break;
                case NativeIOConstants.ErrorNotReady:
                    status = OpenFileStatus.ErrorNotReady;
                    break;
                case NativeIOConstants.FveLockedVolume:
                    status = OpenFileStatus.FveLockedVolume;
                    break;
                case NativeIOConstants.ErrorInvalidParameter:
                    // Contract.Assume(!handleIsValid);

                    // Experimentally, it seems OpenFileById throws ERROR_INVALID_PARAMETER if the file ID doesn't exist.
                    // This is very unfortunate, since that is also used for e.g. invalid sizes for FILE_ID_DESCRIPTOR. Oh well.
                    status = openingById ? OpenFileStatus.FileNotFound : OpenFileStatus.UnknownError;
                    break;
                case NativeIOConstants.ErrorFileExists:
                case NativeIOConstants.ErrorAlreadyExists:
                    if (!handleIsValid)
                    {
                        // Contract.Assume(creationDisposition == FileMode.CreateNew);
                        status = OpenFileStatus.FileAlreadyExists;
                    }
                    else
                    {
                        // Contract.Assert(modeDistinguishesExistence);
                        status = OpenFileStatus.Success;
                        openedOrTruncatedExistingFile = true;
                    }

                    break;
                case NativeIOConstants.ErrorTimeout:
                    status = OpenFileStatus.Timeout;
                    break;
                case NativeIOConstants.ErrorCantAccessFile:
                    status = OpenFileStatus.CannotAccessFile;
                    break;
                case NativeIOConstants.ErrorBadPathname:
                    status = OpenFileStatus.BadPathname;
                    break;
                default:
                    // Contract.Assume(!handleIsValid);
                    status = OpenFileStatus.UnknownError;
                    break;
            }

            bool succeeded = status == OpenFileStatus.Success;
            // Contract.Assert(succeeded || !openedOrTruncatedExistingFile);
            // Contract.Assert(handleIsValid == succeeded);

            return new OpenFileResult(path, status, nativeErrorCode, openedOrTruncatedExistingFile);
        }

        /// <inheritdoc />
        public bool Succeeded => Status == OpenFileStatus.Success;

        /// <inheritdoc />
        public bool Equals(OpenFileResult other)
        {
            return other.NativeErrorCode == NativeErrorCode &&
                    other.OpenedOrTruncatedExistingFile == OpenedOrTruncatedExistingFile &&
                    other.Status == Status;
        }

        /// <inheritdoc />
        public override bool Equals(object? obj)
        {
            // return StructUtilities.Equals(this, obj);
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            return NativeErrorCode + (OpenedOrTruncatedExistingFile ? 1 : 0) | ((short)Status << 16);
        }

        /// <nodoc />
        public static bool operator ==(OpenFileResult left, OpenFileResult right)
        {
            return left.Equals(right);
        }

        /// <nodoc />
        public static bool operator !=(OpenFileResult left, OpenFileResult right)
        {
            return !left.Equals(right);
        }
    }

    /// <summary>
    /// Set of extension methods for <see cref="OpenFileResult"/>.
    /// </summary>
    public static class OpenFileResultExtensions
    {
        // /// <summary>
        // /// Throws an exception if the native error code could not be canonicalized (a fairly exceptional circumstance).
        // /// </summary>
        // /// <remarks>
        // /// This is a good <c>default:</c> case when switching on every possible <see cref="OpenFileStatus"/>
        // /// </remarks>
        // public static Exception ThrowForUnknownError(this OpenFileResult result)
        // {
        //     Contract.Requires(result.Status == OpenFileStatus.UnknownError);
        //     throw result.CreateExceptionForError();
        // }

        // /// <summary>
        // /// Throws an exception if the native error code was canonicalized (known and common, but not handled by the caller).
        // /// </summary>
        // public static Exception ThrowForKnownError(this OpenFileResult result)
        // {
        //     Contract.Requires(result.Status != OpenFileStatus.UnknownError && result.Status != OpenFileStatus.Success);
        //     throw result.CreateExceptionForError();
        // }

        // /// <summary>
        // /// Throws an exception for a failed open.
        // /// </summary>
        // public static Exception ThrowForError(this OpenFileResult result)
        // {
        //     Contract.Requires(result.Status != OpenFileStatus.Success);
        //     throw result.Status == OpenFileStatus.UnknownError ? result.ThrowForUnknownError() : result.ThrowForKnownError();
        // }

        // /// <summary>
        // /// Creates (but does not throw) an exception for this result. The result must not be successful.
        // /// </summary>
        // public static Exception CreateExceptionForError(this OpenFileResult result)
        // {
        //     Contract.Requires(result.Status != OpenFileStatus.Success);
        //     return new NativeWin32Exception(result.NativeErrorCode, GetErrorOrFailureMessage(result));
        // }

        // /// <summary>
        // /// Creates a <see cref="Failure"/> representing this result. The result must not be successful.
        // /// </summary>
        // public static Failure CreateFailureForError(this OpenFileResult result)
        // {
        //     Contract.Requires(result.Status != OpenFileStatus.Success);
        //     return new NativeFailure(result.NativeErrorCode).Annotate(GetErrorOrFailureMessage(result));
        // }

        // /// <summary>
        // /// Returns a string representing information about the <see cref="OpenFileResult"/> error.
        // /// </summary>
        // private static string GetErrorOrFailureMessage(OpenFileResult result)
        // {
        //     var message = result.Status == OpenFileStatus.UnknownError 
        //                     ? "Opening a file handle failed" 
        //                     : $"Opening a file handle failed: {result.Status:G}";

        //     if (result.Status.ImpliesOtherProcessBlockingHandle() && result.Path != null)
        //     {
        //         message += Environment.NewLine;
        //         message += FileUtilities.TryFindOpenHandlesToFile(result.Path, out var info)
        //             ? info
        //             : "Attempt to find processes with open handles to the file failed.";
        //     }

        //     return message;
        // }
    }
}