import pefile

def get_exported_functions(dll_path):
    try:
        # Load the DLL file
        pe = pefile.PE(dll_path)

        # Check if the DLL has an export table
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = pe.DIRECTORY_ENTRY_EXPORT.symbols

            # Iterate over the exported functions
            for export in exports:
                if export.name:
                    function_name = export.name.decode('utf-8')
                    ordinal = export.ordinal
                    print(f"#pragma comment(linker,\"/export:{function_name}=C:\\\Windows\\\System32\\\{dll_path}.{function_name},@{ordinal}\")")
                else:
                    print(f"Ordinal: {export.ordinal}, No name")

        else:
            print("No export table found in the DLL.")

    except pefile.PEFormatError as e:
        print(f"Error parsing the DLL file: {e}")

    finally:
        if 'pe' in locals():
            pe.close()

# Example usage
dll_path = 'cscapi.dll'  # Replace with the path to your DLL file
get_exported_functions(dll_path)
