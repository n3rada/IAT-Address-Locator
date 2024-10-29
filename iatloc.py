# Built-in imports
import argparse

# Third party libraries
import pykd


def get_os_version() -> dict:
    """Retrieve the current OS version and patch level using vertarget."""
    try:
        vertarget_output = pykd.dbgCommand("vertarget")
        os_info = {}

        # Parse relevant details from the vertarget output
        for line in vertarget_output.splitlines():
            if "Windows" in line:
                os_info["Version"] = line.strip()
            elif "Product:" in line:
                os_info["Product"] = line.split(",")[0].split(":")[1].strip()
            elif "rs" in line or "release" in line:
                os_info["Build Info"] = line.strip()

            if "x86" in line:
                os_info["Architecture"] = "x86"
            elif "x64" in line:
                os_info["Architecture"] = "x64"

        return os_info

    except Exception as e:
        pykd.dprintln(f"Error retrieving OS version: {e}")
        return None


def banner():
    pykd.dprintln(
        """
======================================================================
                        IAT Address Locator
======================================================================
"""
    )

    # Fetch OS version details
    os_info = get_os_version()
    if os_info:
        pykd.dprintln(f"OS Version: {os_info.get('Version', 'Unknown')}")
        pykd.dprintln(f"Architecture: {os_info.get('Architecture', 'Unknown')}")
        pykd.dprintln(f"Product: {os_info.get('Product', 'Unknown')}")
        pykd.dprintln(f"Build Info: {os_info.get('Build Info', 'Unknown')}")
    else:
        pykd.dprintln("Unable to retrieve OS version and patch level.")
    pykd.dprintln(
        "\n======================================================================\n"
    )


def get_module_base(module_name: str) -> int:
    """Retrieve the base address of a module."""
    return pykd.module(module_name).begin()


def get_iat_rva_and_size(module_name: str) -> tuple:
    """Retrieve the Relative Virtual Address (RVA) and size of the Import Address Table (IAT) for a specified module.

    This function uses the `!dh` command in WinDbg to examine the headers of a specified module
    and extracts the RVA and size of the Import Address Table Directory.

    Args:
        module_name (str): The name of the module for which to retrieve the IAT's RVA and size.

    Returns:
        tuple: A tuple containing:
            - rva (int): The Relative Virtual Address of the IAT, or `None` if not found.
            - size (int): The size of the IAT, or `None` if not found.

    """
    dh_output = pykd.dbgCommand(f"!dh {module_name} -f")
    for line in dh_output.splitlines():
        if "Import Address Table Directory" in line:
            # ['4A000', '[', '28C]', 'address', '[size]', 'of', 'Import', 'Address', 'Table', 'Directory']
            parts = line.split()
            rva = parts[0]
            size = parts[2][:-1]

            return int(rva, 16), int(size, 16)

    return None, None


def get_iat_entries(module_name: str) -> list:
    """
    Retrieve the Import Address Table (IAT) entries for a specified module.

    This function locates the Import Address Table (IAT) in the specified module
    and retrieves each entry, which includes the address in the IAT, the pointer
    to the function, and the associated symbol name if available.

    Args:
        module_name (str): The name of the module from which to retrieve the IAT entries.

    Returns:
        list: A list of tuples, where each tuple contains:
            - entry_address (int): The address within the IAT where the function pointer is located.
            - function_pointer (int): The pointer to the actual function in the module.
            - symbol (str): The symbol name associated with the function pointer, if available.
    """
    base_address = get_module_base(module_name)
    if not base_address:
        return []

    # Get the IAT RVA and size using !dh
    iat_rva, iat_size = get_iat_rva_and_size(module_name)
    if iat_rva is None or iat_size == 0:
        pykd.dprintln("[x] Could not locate IAT")
        return []

    pykd.dprintln("[+] IAT Found")
    pykd.dprintln(f"|-> RVA: {hex(iat_rva)}")
    pykd.dprintln(f"|-> Size: {hex(iat_size)}")

    # Read IAT entries and format output
    iat_start = base_address + iat_rva
    iat_end = iat_start + iat_size

    pykd.dprintln(f"|-> Address range: {hex(iat_start)} to {hex(iat_end)}\n")

    iat_entries = []

    # List to hold each entry as a dictionary
    iat_entries = []

    # Parse each line from the dps output
    for line in pykd.dbgCommand(f"dps {hex(iat_start)} {hex(iat_end)}").splitlines():
        parts = line.split(maxsplit=2)  # Allow up to 3 parts

        # Determine entry contents based on split results
        if len(parts) == 2:
            entry_address, function_pointer = parts
            symbol = ""
        elif len(parts) == 3:
            entry_address, function_pointer, symbol = parts
        else:
            # Skip malformed lines
            continue

        iat_entries.append((int(entry_address, 16), int(function_pointer, 16), symbol))

    return iat_entries


def resolve_function(full_function_name: str) -> tuple:
    """
    Resolve the memory address of a specified function, including common variations.

    This function attempts to locate the memory address of a given function by using the
    WinDbg `x` (examine symbols) command. It first tries the exact function name provided,
    and if not found, it checks for common variations such as `Stub`, `A` (ANSI), and `W`
    (Unicode) suffixes. If multiple addresses are returned, the function logs a warning
    and defaults to using the first address.

    Args:
        full_function_name (str): The fully qualified name of the function to resolve
                                  (e.g., "KERNEL32!VirtualAlloc").

    Returns:
        tuple: A tuple containing:
            - address (int): The resolved memory address of the function, or 0 if not found.
            - symbol_name (str): The symbol name of the function, or an empty string if not found.
    """
    # Primary search
    output = pykd.dbgCommand(f"x {full_function_name}")
    if not output:
        # Try known variations, such as `Stub` or ANSI/Unicode suffixes
        suffix_variants = ["Stub", "A", "W"]
        for suffix in suffix_variants:
            output = pykd.dbgCommand(f"x {full_function_name}{suffix}")
            if output:
                break
        else:
            pykd.dprintln(f"[x] Could not resolve {full_function_name}")
            return 0, ""

    # Parse the output, handle cases where multiple results are returned
    addresses = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            address_str, symbol_name = parts[0], parts[1]
            try:
                address = int(address_str, 16)
                addresses.append((address, symbol_name))
            except ValueError:
                continue

    # Return the first match found, or notify if multiple matches exist
    if not addresses:
        pykd.dprintln(f"[x] No valid address found for {full_function_name}")
        return 0, ""
    elif len(addresses) > 1:
        pykd.dprintln(
            f"[!] Multiple matches found for {full_function_name}, using first match: {addresses[0][1]}"
        )

    return addresses[0]  # Return the first match (address, symbol name)


def get_suitable_modules() -> list:
    """
    Retrieve a list of non-ASLR modules suitable for DEP bypass, excluding those with 0x00 in the upper address bytes.

    This function runs the `!nmod` command to list modules and filters the output for modules
    that do not have ASLR enabled. It also excludes modules with null bytes (0x00) in the upper
    address bytes.

    Raises:
        ModuleNotFoundError: Raised if the narly extension cannot be loaded to provide `!nmod`.

    Returns:
        list: A list of module names that meet the non-ASLR and non-null-byte criteria.
    """
    nmod_output = pykd.dbgCommand("!nmod")

    # If the command does not work, try loading the narly extension
    if nmod_output is None:
        load_output = pykd.dbgCommand(".load narly")

        if "!nmod" not in load_output:
            raise ModuleNotFoundError("Failed to load the Narly extension.")

        return get_suitable_modules()

    results = []

    # Process nmod_output to look for non-ASLR modules with no 0x00 in the upper address bytes
    for line in nmod_output.splitlines():
        # Modules are ordered, so if we reach "*ASLR" entries, stop processing
        if "*ASLR" in line:
            break

        parts = line.split()
        module_name = parts[2]
        base_address = parts[0]

        # Check for null bytes
        if not base_address.startswith("00"):
            results.append(module_name)

    return results


def main():
    parser = argparse.ArgumentParser(
        prog="iatloc",
        add_help=True,
        description="Find the pointer to the function inside the IAT of a module.",
    )
    parser.add_argument(
        "module",
        type=str,
        nargs="?",
        help="Enter module name (e.g., KERNEL32!VirtualAllocStub)",
    )

    parser.add_argument(
        "function",
        type=str,
        help="Enter function name to search in the IAT",
    )

    args = parser.parse_args()

    banner()

    module_name = args.module

    # USER32!PostMessageA
    # KERNEL32!VirtualAllocStub
    # Parse module and function if "!" is present in function_name
    if "!" in args.function:
        specified_module, function_name = args.function.split("!", 1)
    else:
        specified_module = "KERNEL32"
        function_name = args.function

    target_address, symbol_name = resolve_function(
        f"{specified_module}!{function_name}"
    )

    if not target_address:
        pykd.dprintln(f"[x] Could not resolve {specified_module}!{function_name}")
        return

    pykd.dprintln(f"[+] {symbol_name} is located at {hex(target_address)}\n")

    if args.module is None:
        suitable_modules = get_suitable_modules()
        pykd.dprintln("[*] Checking in all suitable non-ASLR modules")
        for module in suitable_modules:
            pykd.dprintln(f"|-> {module}")

        # Iterate through modules and perform IAT search in each
        for module_name in suitable_modules:
            base_address = get_module_base(module_name)
            if not base_address:
                pykd.dprintln(f"[x] Failed to retrieve base address for {module_name}")
                return

            pykd.dprintln(
                f"\n================= Searching in {module_name} ({hex(base_address)})"
            )

            for entry_address, function_pointer, symbol in get_iat_entries(module_name):
                if symbol_name in symbol:
                    pykd.dprintln(f"[+] Found {symbol}")
                    pykd.dprintln(f"|-> IAT address: {hex(entry_address)}")
                    pykd.dprintln(f"|-> Points to: {hex(function_pointer)}")
                    break
            else:
                pykd.dprintln(f"[x] {symbol_name} not found")
    else:

        base_address = get_module_base(module_name)
        if not base_address:
            pykd.dprintln(f"[x] Failed to retrieve base address for {module_name}")
            return

        pykd.dprintln(
            f"\n================= Searching in {module_name} ({hex(base_address)})"
        )

        iat_entries = get_iat_entries(module_name)

        for entry_address, function_pointer, symbol in iat_entries:
            if symbol_name in symbol:
                # Found it!
                pykd.dprintln(f"[+] Found {symbol}")
                pykd.dprintln(f"|-> IAT address: {hex(entry_address)}")
                pykd.dprintln(f"|-> Points to: {hex(function_pointer)}")
                break

        else:
            pykd.dprintln(f"[x] {symbol_name} not found")
            # Didn't find anything..
            pykd.dprintln("\n[+] Use subsidiary functions to reach your needs")
            pykd.dprintln(f"[i] Offset = {symbol_name} - <subsidiary_function>")

            subsidiary_functions = [
                "KERNEL32!VirtualAllocStub",
                "KERNEL32!WriteFile",
                "KERNEL32!LoadLibraryAStub",
                "KERNEL32!GetLastError",
                "KERNEL32!GetProcAddressStub",
                "KERNEL32!CloseHandle",
                "KERNEL32!Sleep",
                "KERNEL32!HeapAlloc",
            ]

            for function in subsidiary_functions:
                function_address, _ = resolve_function(function)

                if function_address == 0:
                    continue  # Skip if function not found

                for entry_address, function_pointer, symbol in iat_entries:
                    if function in symbol:
                        # Calculate offset and negated offset
                        offset = target_address - function_address
                        neg_offset = (
                            0xFFFFFFFF - abs(offset) + 1
                        ) & 0xFFFFFFFF  # 32-bit negation

                        pykd.dprintln(f"\n[+] Found {symbol}")
                        pykd.dprintln(f"|-> IAT adddress: {hex(entry_address)}")
                        pykd.dprintln(f"|-> Points to: {hex(function_pointer)}")
                        pykd.dprintln(f"|-> Offset: {hex(offset)}")
                        pykd.dprintln(f"|-> Negated offset: {hex(neg_offset)}")
                        break

            pykd.dprintln(
                "\n[i] Each offset will always remain the same for the current patch level and OS version"
            )

    pykd.dprintln("\n[+] Done")


if __name__ == "__main__":
    main()
