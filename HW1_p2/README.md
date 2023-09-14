
# HW1_464

**Instructions to Run:**
- Use the Makefile to compile the code.
- Run `make clean` to remove all executable files.

**To Run the Server and Client:**
1. Open one terminal shell.
2. Enter the following command:
   ```
   ./server
   ```
3. Open another terminal shell.
4. Enter the following command, replacing `<SHA1 PIN HASH>` with the actual SHA1 PIN hash:
   ```
   ./pincrack <SHA1 PIN HASH>
   ```

**To Run `strace` with Time:**
- Run the following command:
   ```
   make trace_pincracktest
   ```

