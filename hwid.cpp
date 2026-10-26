// hwid.cpp

#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <scsi.h>
#include <intrin.h>
#include "defs.h"
#include "log.h"
#include <cstdint>

// ============================================================
// manual declarations — not exposed by ntddk.h
// ============================================================

void spoof17864688_serial(char* serial, bool is_smart);
void spoof17864688_serial_bounded(char* serial, size_t max_len, bool is_smart);
PDRIVER_DISPATCH find_original_dispatch(PDRIVER_OBJECT driver_object); // ← add

typedef struct _IDENTIFY_DEVICE_DATA {
    UCHAR  Raw[20];
    UCHAR  SerialNumber[20];
    UCHAR  Trailing[472];
} IDENTIFY_DEVICE_DATA, * PIDENTIFY_DEVICE_DATA;

// ============================================================
// globals
// ============================================================
PDRIVER_DISPATCH g_original_device_control;
unsigned long long g_startup_time;

unsigned long long g_cached_seed = 0;
bool g_seed_valid = false;

void spoof17864688_serial(char* serial, bool is_smart);
void spoof17864688_serial_bounded(char* serial, size_t max_len, bool is_smart); // ← add

// ============================================================
// splitmix64 PRNG
// ============================================================
static uint64_t splitmix64(uint64_t& state)
{
    uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline char random_digit_char7864688(uint64_t& state) { return '1' + (splitmix64(state) % 9); }
static inline char random_upper_char7864688(uint64_t& state) { return 'A' + (splitmix64(state) % 26); }
static inline char random_lower_char7864688(uint64_t& state) { return 'a' + (splitmix64(state) % 26); }

// ============================================================
// structures
// ============================================================
struct REQUEST_STRUCT
{
    PIO_COMPLETION_ROUTINE OldRoutine;
    PVOID OldContext;
    ULONG OutputBufferLength;
    PVOID SystemBuffer;
    PEPROCESS CallerProcess; // captured at dispatch — caller's thread context
};


// ============================================================
// hex/char helpers
// ============================================================
static inline bool is_good_char7864688(char c)
{
    const auto u = uint8_t(c);
    return (u >= uint8_t('0') && u <= uint8_t('9')) ||
        (u >= uint8_t('A') && u <= uint8_t('Z')) ||
        (u >= uint8_t('a') && u <= uint8_t('z'));
}

static inline bool is_hex7864688(char c)
{
    const auto u = uint8_t(c);
    return (u >= uint8_t('0') && u <= uint8_t('9')) ||
        (u >= uint8_t('A') && u <= uint8_t('F')) ||
        (u >= uint8_t('a') && u <= uint8_t('f'));
}

static inline uint8_t unhex_char7864688(char c)
{
    const auto u = uint8_t(c);
    if (u >= uint8_t('0') && u <= uint8_t('9')) return u - uint8_t('0');
    if (u >= uint8_t('A') && u <= uint8_t('F')) return u - uint8_t('A') + 0xA;
    if (u >= uint8_t('a') && u <= uint8_t('f')) return u - uint8_t('a') + 0xa;
    return 0xFF;
}

static inline uint8_t unhex_byte7864688(char a, char b)
{
    return (unhex_char7864688(a) << 4) + unhex_char7864688(b);
}

static inline char hex_char7864688(uint8_t v)
{
    if (v < 0xA) return char(uint8_t('0') + v);
    return char(uint8_t('A') + v - 0xA);
}

struct hex_pair_t
{
    char first;
    char second;
};

static inline hex_pair_t hex_byte7864688(uint8_t v)
{
    return { hex_char7864688(v >> 4), hex_char7864688(v & 0xF) };
}

static inline bool is_digit_char7864688(char c) { return c >= '0' && c <= '9'; }
static inline bool is_letter_char7864688(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

// ============================================================
// CDB classifiers — shared between dispatch and completion
// ============================================================
static inline bool cdb_is_inquiry_serial(const uint8_t* cdb, uint32_t cdb_len)
{
    return cdb_len >= 6 && cdb[0] == SCSIOP_INQUIRY && (cdb[1] & 0x01) && cdb[2] == 0x80;
}

// ============================================================
// FIXED classifier — ATA_16 COMMAND lives at CDB[14] per SAT
// ============================================================
static inline bool cdb_is_ata_identify(const uint8_t* cdb, uint32_t cdb_len)
{
    // ATA_12: opcode 0xA1, COMMAND at CDB[9]
    if (cdb_len == 12 && cdb[0] == 0xA1)
        return cdb[9] == 0xEC;

    // ATA_16: opcode 0x85, COMMAND at CDB[14]  ← was CDB[4], wrong
    if (cdb_len == 16 && cdb[0] == 0x85)
        return cdb[14] == 0xEC;

    return false;
}

// ============================================================
// seed loading — PASSIVE only, from DriverEntry
// ============================================================
#define SEED_FILE_PATH7864688 L"\\??\\C:\\Windows\\Fonts\\seed.txt"

static bool ParseHexStringToUint647864688(const char* str, unsigned long long& value)
{
    value = 0;
    while (*str)
    {
        char c = *str++;
        unsigned int digit = 0;

        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else return false;

        value = (value << 4) | digit;
    }
    return true;
}

static bool ReadSeedFromFile7864688(unsigned long long& seed)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return false;

    HANDLE file_handle;
    OBJECT_ATTRIBUTES object_attributes;
    IO_STATUS_BLOCK io_status_block;
    UNICODE_STRING file_path;
    LARGE_INTEGER file_offset;
    char buffer[64];

    RtlInitUnicodeString(&file_path, SEED_FILE_PATH7864688);
    InitializeObjectAttributes(&object_attributes, &file_path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = ZwCreateFile(&file_handle, GENERIC_READ, &object_attributes,
        &io_status_block, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

    if (!NT_SUCCESS(status))
    {
        Log::Print("%s %d : Failed to open seed file: %08X\n", __FUNCTION__, __LINE__, status);
        return false;
    }

    file_offset.QuadPart = 0;
    status = ZwReadFile(file_handle, NULL, NULL, NULL, &io_status_block,
        buffer, sizeof(buffer) - 1, &file_offset, NULL);
    ZwClose(file_handle);

    if (!NT_SUCCESS(status))
    {
        Log::Print("%s %d : Failed to read seed: %08X\n", __FUNCTION__, __LINE__, status);
        return false;
    }

    const auto bytes_read = (ULONG)io_status_block.Information;
    if (bytes_read >= sizeof(buffer))
        return false;

    buffer[bytes_read] = '\0';
    return ParseHexStringToUint647864688(buffer, seed);
}

// ============================================================
// serial randomization — splitmix64, DISPATCH-safe
// ============================================================
static void randomize_subserial7864688(char* serial, size_t len)
{
    if (!g_seed_valid)
        return;

    uint64_t prng_state = g_cached_seed;

    for (size_t i = 0; i < len; ++i)
    {
        char c = serial[i];

        if (c == '0')
            continue;
        else if (is_digit_char7864688(c))
            serial[i] = random_digit_char7864688(prng_state);
        else if (is_letter_char7864688(c))
        {
            if (c >= 'a' && c <= 'z')
                serial[i] = random_lower_char7864688(prng_state);
            else if (c >= 'A' && c <= 'Z')
                serial[i] = random_upper_char7864688(prng_state);
        }
    }
}

// ============================================================
// SPTD data spoof — works on a raw data pointer + CDB snapshot.
// called from: dispatch inline (caller context), completion (kernel VA),
// or deferred worker (attached process). SEH is the caller's job.
// ============================================================
// ============================================================
// SPTD deferred worker — ONLY for genuinely-pending async IRPs.
// attaches to the process captured at DISPATCH (correct one).
// ============================================================

// ============================================================
// IOC_REQUEST — matching reference style
// ============================================================
// ============================================================
// IOC_REQUEST — matching reference style
// ============================================================
// ============================================================
// IOC_REQUEST — CallerProcess back in, captured at dispatch
// ============================================================
// ============================================================
// IOC_REQUEST — add our MDL
// ============================================================
typedef struct _IOC_REQUEST
{
    PIO_COMPLETION_ROUTINE OldRoutine;
    PVOID OldContext;
    ULONG BufferLength;
    PVOID Buffer;
    PMDL DataMdl;
} IOC_REQUEST, * PIOC_REQUEST;

// ============================================================
// SPTD completion — direct access, reference style
// ============================================================
// ============================================================
// DISPATCH-safe logging — DbgPrint only, no file I/O
// ============================================================
// ============================================================
// DISPATCH-safe logging — DbgPrint only, no file I/O
// ============================================================
#define TRACE_SPTD(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[hwid] " fmt "\n", __VA_ARGS__)

// ============================================================
// kernel-VA check — only touch DataBuffer at DISPATCH if it's
// guaranteed valid in every address space
// ============================================================
static inline bool is_kernel_va7864688(const void* p)
{
    return p && (uintptr_t)p >= 0xFFFF800000000000ULL;
}

NTSTATUS SCSIDirect7864688(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    if (context)
    {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePoolWithTag(context, 'rqST');

        if (NT_SUCCESS(irp->IoStatus.Status))
        {
            auto ptd = (PSCSI_PASS_THROUGH_DIRECT)request.Buffer;

            if (request.BufferLength >= sizeof(SCSI_PASS_THROUGH_DIRECT) && ptd)
            {
                const bool ata = cdb_is_ata_identify(ptd->Cdb, ptd->CdbLength);
                const bool inq = cdb_is_inquiry_serial(ptd->Cdb, ptd->CdbLength);

                uint8_t* data_ptr = nullptr;

                if (is_kernel_va7864688(ptd->DataBuffer))
                    data_ptr = (uint8_t*)ptd->DataBuffer; // kernel caller
                else if (request.DataMdl)
                    data_ptr = (uint8_t*)MmGetSystemAddressForMdlSafe(request.DataMdl, NormalPagePriority);

                const auto data_len = ptd->DataTransferLength;

                TRACE_SPTD("completion: cdb0=%02X dlen=%u sysva=%p irql=%u",
                    ptd->Cdb[0], data_len, data_ptr, KeGetCurrentIrql());

                if (data_ptr && (ata || inq) && data_len > 0)
                {
                    __try
                    {
                        if (ata && data_len >= 512)
                        {
                            auto idData = (PIDENTIFY_DEVICE_DATA)data_ptr;

                            char serial_buf[21];
                            RtlCopyBytes(serial_buf, idData->SerialNumber, 20);
                            serial_buf[20] = '\0';

                            for (auto i = 0u; i < 20; i += 2)
                            {
                                const char t = serial_buf[i];
                                serial_buf[i] = serial_buf[i + 1];
                                serial_buf[i + 1] = t;
                            }

                            TRACE_SPTD("SPTD ATA Serial0: %s", serial_buf);
                            spoof17864688_serial_bounded(serial_buf, 20, true);
                            TRACE_SPTD("SPTD ATA Serial1: %s", serial_buf);

                            for (auto i = 0u; i < 20; i += 2)
                            {
                                const char t = serial_buf[i];
                                serial_buf[i] = serial_buf[i + 1];
                                serial_buf[i + 1] = t;
                            }

                            RtlCopyBytes(idData->SerialNumber, serial_buf, 20);
                        }
                        else if (inq && data_len >= 4)
                        {
                            auto vpd = data_ptr;
                            const auto vpd_len = (vpd[2] << 8) | vpd[3];

                            if (vpd_len > 0 && 4 + vpd_len <= (int)data_len)
                            {
                                char serial_buf[65] = {};
                                const auto copy_len = vpd_len < (int)sizeof(serial_buf) - 1
                                    ? vpd_len : (int)sizeof(serial_buf) - 1;
                                RtlCopyBytes(serial_buf, vpd + 4, copy_len);

                                TRACE_SPTD("SPTD INQUIRY Serial0: %s", serial_buf);
                                spoof17864688_serial_bounded(serial_buf, copy_len, false);
                                TRACE_SPTD("SPTD INQUIRY Serial1: %s", serial_buf);

                                RtlCopyBytes(vpd + 4, serial_buf, copy_len);
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        TRACE_SPTD("SEH in SPTD spoof");
                    }
                }
            }
        }

        // release our lock — spoof is already written into the pages
        if (request.DataMdl)
        {
            MmUnlockPages(request.DataMdl);
            IoFreeMdl(request.DataMdl);
        }

        if (request.OldRoutine && irp->StackCount > 1)
            return request.OldRoutine(device, irp, request.OldContext);
    }

    return STATUS_SUCCESS;
}
// ============================================================
// completion: STORAGE_QUERY_PROPERTY — kernel buffer, DISPATCH-safe
// ============================================================
NTSTATUS completed_storage_query7864688(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
    if (!context)
        return STATUS_SUCCESS;

    const auto request = (REQUEST_STRUCT*)context;
    const auto buffer_length = request->OutputBufferLength;
    const auto buffer = (PSTORAGE_DEVICE_DESCRIPTOR)request->SystemBuffer;
    const auto old_routine = request->OldRoutine;
    const auto old_context = request->OldContext;
    ExFreePoolWithTag(context, 'rqST');

    do
    {
        if (!NT_SUCCESS(irp->IoStatus.Status))
            break;

        if (buffer_length < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties))
            break;

        if (buffer->SerialNumberOffset == 0)
            break;

        if (buffer_length < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties) + buffer->RawPropertiesLength
            || buffer->SerialNumberOffset < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties)
            || buffer->SerialNumberOffset >= buffer_length)
        {
            Log::Print("%s %d : Malformed buffer size: %d\n", __FUNCTION__, __LINE__, buffer_length);
        }
        else
        {
            auto serial = (char*)buffer + buffer->SerialNumberOffset;
            // bound = bytes from serial start to end of the descriptor buffer
            const auto max_len = buffer_length - buffer->SerialNumberOffset;
            spoof17864688_serial_bounded(serial, max_len, false);
        }
    } while (false);

    if (irp->StackCount > 1ul && old_routine)
        return old_routine(device_object, irp, old_context);

    return STATUS_SUCCESS;
}

// ============================================================
// completion: SMART — kernel buffer, DISPATCH-safe
// ============================================================
NTSTATUS completed_smart7864688(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
    UNREFERENCED_PARAMETER(device_object);

    if (!context)
        return irp->IoStatus.Status;

    const auto request = (REQUEST_STRUCT*)context;
    const auto buffer_length = request->OutputBufferLength;
    const auto buffer = (SENDCMDOUTPARAMS*)request->SystemBuffer;
    const auto old_routine = request->OldRoutine;
    const auto old_context = request->OldContext;
    ExFreePoolWithTag(context, 'rqST');

    if (buffer_length < FIELD_OFFSET(SENDCMDOUTPARAMS, bBuffer)
        || FIELD_OFFSET(SENDCMDOUTPARAMS, bBuffer) + buffer->cBufferSize > buffer_length
        || buffer->cBufferSize < sizeof(IDINFO))
    {
        Log::Print("%s %d : Malformed buffer size: %d\n", __FUNCTION__, __LINE__, buffer_length);
    }
    else if (NT_SUCCESS(irp->IoStatus.Status))
    {
        const auto info = (IDINFO*)buffer->bBuffer;
        char serial[21];
        RtlCopyMemory(serial, info->sSerialNumber, 20);
        serial[20] = '\0';

        for (auto i = 0u; i < 20; i += 2)
        {
            const char t = serial[i];
            serial[i] = serial[i + 1];
            serial[i + 1] = t;
        }

        // ... after word-swap into serial[]:
        spoof17864688_serial_bounded(serial, 20, true);

        for (auto i = 0u; i < 20; i += 2)
        {
            const char t = serial[i];
            serial[i] = serial[i + 1];
            serial[i + 1] = t;
        }

        RtlCopyMemory(info->sSerialNumber, serial, 20);
    }

    if (irp->StackCount > 1ul && old_routine)
        return old_routine(device_object, irp, old_context);

    return irp->IoStatus.Status;
}

// ============================================================
// completion: SCSI_PASS_THROUGH — kernel buffer, DISPATCH-safe
// ============================================================
NTSTATUS completed_scsi_passthrough7864688(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
    if (!context)
        return STATUS_SUCCESS;

    const auto request = (REQUEST_STRUCT*)context;
    const auto buffer_length = request->OutputBufferLength;
    const auto buffer = (PSCSI_PASS_THROUGH)request->SystemBuffer;
    const auto old_routine = request->OldRoutine;
    const auto old_context = request->OldContext;
    ExFreePoolWithTag(context, 'rqST');

    do
    {
        if (!NT_SUCCESS(irp->IoStatus.Status))
            break;

        if (buffer_length < sizeof(SCSI_PASS_THROUGH))
            break;

        const auto cdb = buffer->Cdb;
        const auto cdb_len = buffer->CdbLength;

        if (cdb_is_inquiry_serial(cdb, cdb_len))
        {
            const auto data_offset = buffer->DataBufferOffset;
            const auto data_len = buffer->DataTransferLength;
            if (data_len < 4 || data_offset + data_len > buffer_length)
                break;

            auto vpd = (uint8_t*)((uintptr_t)buffer + data_offset);
            const auto vpd_len = (vpd[2] << 8) | vpd[3];
            if (vpd_len == 0 || 4 + vpd_len > data_len)
                break;

            char serial_buf[65] = {};
            const auto copy_len = vpd_len < sizeof(serial_buf) - 1 ? vpd_len : sizeof(serial_buf) - 1;
            RtlCopyMemory(serial_buf, vpd + 4, copy_len);

            spoof17864688_serial(serial_buf, false);
            RtlCopyMemory(vpd + 4, serial_buf, copy_len);
        }
        else if (cdb_is_ata_identify(cdb, cdb_len))
        {
            const auto data_offset = buffer->DataBufferOffset;
            const auto data_len = buffer->DataTransferLength;
            if (data_len < 512 || data_offset + data_len > buffer_length)
                break;

            auto identify = (uint8_t*)((uintptr_t)buffer + data_offset);
            char* serial_ptr = (char*)(identify + 20);

            char serial_buf[21];
            RtlCopyMemory(serial_buf, serial_ptr, 20);
            serial_buf[20] = '\0';

            for (auto i = 0u; i < 20; i += 2)
            {
                const char t = serial_buf[i];
                serial_buf[i] = serial_buf[i + 1];
                serial_buf[i + 1] = t;
            }

            spoof17864688_serial(serial_buf, true);

            for (auto i = 0u; i < 20; i += 2)
            {
                const char t = serial_buf[i];
                serial_buf[i] = serial_buf[i + 1];
                serial_buf[i + 1] = t;
            }

            RtlCopyMemory(serial_ptr, serial_buf, 20);
        }
    } while (false);

    if (irp->StackCount > 1ul && old_routine)
        return old_routine(device_object, irp, old_context);

    return STATUS_SUCCESS;
}

// ============================================================
// completion: SCSI_PASS_THROUGH_DIRECT
// — kernel VA  : spoof inline right here (DISPATCH-safe)
// — user VA    : dispatch hook handles the sync case; we only
//                queue the worker when the IRP was genuinely pending
// ============================================================

// ============================================================
// hook installation
// ============================================================
void do_completion_hook7864688(PIRP irp, PIO_STACK_LOCATION ioc, PIO_COMPLETION_ROUTINE routine, PMDL data_mdl)
{
    const auto request = (PIOC_REQUEST)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(IOC_REQUEST), 'rqST');

    if (!request)
    {
        // don't leak locked pages if the hook can't be installed
        if (data_mdl)
        {
            MmUnlockPages(data_mdl);
            IoFreeMdl(data_mdl);
        }
        return;
    }

    const auto old_context = ioc->Context;

    request->OldRoutine = ioc->CompletionRoutine;
    request->OldContext = old_context;
    request->BufferLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;
    request->Buffer = irp->AssociatedIrp.SystemBuffer;
    request->DataMdl = data_mdl;

    ioc->Control = SL_INVOKE_ON_SUCCESS;
    ioc->Context = request;
    ioc->CompletionRoutine = routine;
}

NTSTATUS hooked_device_control7864688(PDEVICE_OBJECT device_object, PIRP irp)
{
    const auto ioc = IoGetCurrentIrpStackLocation(irp);
    const auto original = find_original_dispatch(device_object->DriverObject);

    switch (ioc->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_STORAGE_QUERY_PROPERTY:
    {
        const auto query = (PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer;
        if (query && query->PropertyId == StorageDeviceProperty)
            do_completion_hook7864688(irp, ioc, &completed_storage_query7864688, nullptr);

        return original(device_object, irp);
    }

    case SMART_RCV_DRIVE_DATA:
        do_completion_hook7864688(irp, ioc, &completed_smart7864688, nullptr);
        return original(device_object, irp);

    case IOCTL_SCSI_PASS_THROUGH:
        do_completion_hook7864688(irp, ioc, &completed_scsi_passthrough7864688, nullptr);
        return original(device_object, irp);

    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    {
        auto sptd = (PSCSI_PASS_THROUGH_DIRECT)irp->AssociatedIrp.SystemBuffer;

        PMDL data_mdl = nullptr;

        // caller's thread, PASSIVE — lock the user DataBuffer pages now
        // so completion can map them to a system VA from any process
        if (sptd && sptd->DataBuffer && sptd->DataTransferLength &&
            !is_kernel_va7864688(sptd->DataBuffer) &&
            (cdb_is_ata_identify(sptd->Cdb, sptd->CdbLength) ||
                cdb_is_inquiry_serial(sptd->Cdb, sptd->CdbLength)))
        {
            data_mdl = IoAllocateMdl(sptd->DataBuffer, sptd->DataTransferLength, FALSE, FALSE, nullptr);
            if (data_mdl)
            {
                __try
                {
                    MmProbeAndLockPages(data_mdl, UserMode, IoWriteAccess);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    IoFreeMdl(data_mdl);
                    data_mdl = nullptr;
                }
            }
        }

        do_completion_hook7864688(irp, ioc, &SCSIDirect7864688, data_mdl);

        return original(device_object, irp);
    }

    default:
        return original(device_object, irp);
    }
}

// ============================================================
// multi-driver hook table
// ============================================================
struct DRIVER_HOOK_ENTRY
{
    PDRIVER_OBJECT DriverObject;
    PDRIVER_DISPATCH Original;
};

DRIVER_HOOK_ENTRY g_hooks[4] = {};
ULONG g_hook_count = 0;

static PDRIVER_DISPATCH find_original_dispatch(PDRIVER_OBJECT driver_object)
{
    if (!driver_object)
        return nullptr;

    for (ULONG i = 0; i < g_hook_count; ++i)
        if (g_hooks[i].DriverObject == driver_object)
            return g_hooks[i].Original;

    return nullptr;
}

static void apply_hook_to_driver7864688(PCWSTR driver_name)
{
    UNICODE_STRING uname;
    RtlInitUnicodeString(&uname, driver_name);

    PDRIVER_OBJECT driver_object = nullptr;
    auto status = ObReferenceObjectByName(
        &uname, OBJ_CASE_INSENSITIVE, nullptr, 0,
        *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driver_object);

    if (!driver_object || !NT_SUCCESS(status))
        return;

    auto& dc = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];

    // already ours (re-map over live hook) or full table — don't stack
    if (dc == (PDRIVER_DISPATCH)&hooked_device_control7864688 || g_hook_count >= 4)
    {
        ObDereferenceObject(driver_object);
        return;
    }

    // sanity: the original must be a kernel code pointer before we
    // ever plan to call it
    if ((uintptr_t)dc < 0xFFFF800000000000ULL)
    {
        ObDereferenceObject(driver_object);
        return;
    }

    g_hooks[g_hook_count].DriverObject = driver_object; // keep our ref — no deref for this slot
    g_hooks[g_hook_count].Original = dc;
    ++g_hook_count;

    dc = &hooked_device_control7864688;
}

// ============================================================
// spoof — pure computation, DISPATCH-safe
// ============================================================
// ============================================================
// bounded strlen — never walks past max_len
// ============================================================
static inline size_t bounded_strlen7864688(const char* s, size_t max_len)
{
    size_t len = 0;
    while (len < max_len && s[len])
        ++len;
    return len;
}

// ============================================================
// spoof — BOUNDED version, max_len = bytes we're allowed to touch
// ============================================================
void spoof17864688_serial_bounded(char* serial, size_t max_len, bool is_smart)
{
    if (!serial || max_len == 0)
        return;

    size_t len = bounded_strlen7864688(serial, max_len);
    if (len == 0)
        return;

    bool is_serial_hex;

    char* buf = (char*)ExAllocatePoolWithTag(NonPagedPool, len + 1, 'gat1');
    if (!buf)
        return;

    if (is_smart)
    {
        is_serial_hex = false;
        RtlCopyMemory(buf, serial, len);
    }
    else
    {
        is_serial_hex = true;
        for (size_t i = 0; i < len; ++i)
            if (!is_hex7864688(serial[i]))
                is_serial_hex = false;

        if (is_serial_hex)
        {
            // hex decode: halve, and keep write-back within max_len
            len /= 2;
            for (size_t i = 0u; i < len; ++i)
                buf[i] = unhex_byte7864688(serial[i * 2], serial[i * 2 + 1]);
        }
        else
        {
            RtlCopyMemory(buf, serial, len);
        }
    }

    buf[len] = 0;
    randomize_subserial7864688(buf, len);

    if (is_serial_hex)
    {
        // write-back is len*2 — guaranteed <= original len <= max_len
        for (size_t i = 0u; i < len; ++i)
        {
            const auto t = hex_byte7864688(uint8_t(buf[i]));
            serial[i * 2 + 0] = t.first;
            serial[i * 2 + 1] = t.second;
        }
    }
    else
    {
        RtlCopyMemory(serial, buf, len);
    }

    ExFreePoolWithTag(buf, 'gat1');
}

// keep the old name working so other call sites don't break —
// but they should ALL be migrated to the bounded version
void spoof17864688_serial(char* serial, bool is_smart)
{
    // unbounded fallback — only safe on buffers WE null-terminated
    spoof17864688_serial_bounded(serial, 256, is_smart);
}

// ============================================================
// entry
// ============================================================
extern "C"
NTSTATUS EntryPoint(
    _DRIVER_OBJECT* DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KeQuerySystemTime(&g_startup_time);

    g_seed_valid = ReadSeedFromFile7864688(g_cached_seed);
    if (!g_seed_valid)
        Log::Print("%s %d : Seed not loaded — spoof disabled until reload\n",
            __FUNCTION__, __LINE__);

    apply_hook_to_driver7864688(L"\\Driver\\Disk");
    apply_hook_to_driver7864688(L"\\Driver\\storahci");
    apply_hook_to_driver7864688(L"\\Driver\\stornvme");
    return STATUS_SUCCESS;
}