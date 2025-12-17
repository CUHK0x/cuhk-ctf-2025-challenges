# TL;DR
The program uses an unsafe scheme to serialize the data, allowing the serialization of arbitrary user-defined class. This allows the user to modify `id` field of the class to an `id` that is in use. When there is an existing `id` that is in use, the program attempts to copy two string fields from the newly serialized class to the existing class with `strcpy`, causing a buffer overflow on the heap. The author's solution is to poison vtable pointers of following entries of the class, but other heap exploits may be possible. The ending act is to return to the `win` function.

# Exploitable Conditions
1. `;` is used to delimit values, but it is not filtered / escaped in string inputs. This allows the user to add a chunk with an ID that is in use. This is needed to trigger the `strcpy` code.
2. `strcpy` used to copy strings, causing a heap overflow.
3. A function that allows the user to see the address of some functions in the executable, therefore getting the address of `win`.
4. There is a `win` function that opens a shell.

# Exploit
See `solve.py` for an actual implementation.
## Heap Leak
1. Create a new human. Inside the `occupation` field, inject a serialized version of human that references an instance that will be created later. This new human should have its `name` overflow into the `occupation` field, so that we can corrupt the buffer pointer of `occupation` to point to itself, causing a stack leak. Use the save function.
2. Create some pals to align the memory.
3. Create the human that the serialized payload references.
4. Load the save to trigger buffer overflow.
5. Call print to leak the heap address.
## Vtable poisoning
1. Use the debug function to compute the address of `win`.
2. Inject the address of `win` somewhere, and compute the address where it is stored with the heap leak.
3. Prepare and inject a serialized human in string fields. This will be used to overflow into another one that is consecutive.
4. Create enough stuff so that the next two humans created will be in consectutive chunks.
5. Create two humans that will be used for exploit.
6. Load save to trigger buffer overflow. The `occupation` field of the first chunk will overflow into the second. The vtable ptr field of the second human should point to the address of `win` that we stored.
7. Call print to trigger win.

# Points to note
1. `std::string` stores 15 bytes maximum before allocating a buffer out of its structure to store the string.
2. If a class has virtual functions, the first field of the class will have a pointer to the vtable shared by the same concrete class. For example, all classes of `Human` share the same vtable pointer for `Human`. This is needed to achieve runtime polymorphism.
    ```
    /* offset      |    size */  type = struct Human {
    /*      0      |       8 */    void *vtable;
    /*      8      |       4 */    unsigned int id;
    /* XXX  4-byte hole      */
    /*     16      |      32 */    std::string name;
                                // local buf offset: 16 + 16 = 32
    /*     48      |       4 */    unsigned int age;
    /*     52      |       4 */    LivingThing::Gender gender;
    /*     56      |       4 */    unsigned int hp;
    /* XXX  4-byte padding   */
    /*     64      |      32 */    std::string occupation;
                                /* total size (bytes):   96 */
                                }
    ```
3. Heap offsets are predictable.
