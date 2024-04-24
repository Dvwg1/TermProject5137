import ida_kernwin
import ida_bytes
import ida_lines
import ida_funcs
import ida_segment
import ida_idaapi
from g4f.client import Client
import string
#according to hexrays documentation, ea is "any address belonging to the (a) function" (hex-rays, 2024)
#this is why ea is used


def query(prompt):
        client = Client()
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
            )
        responsestring = response.choices[0].message.content #This allows the creation of test variables
        test_char = response.choices[0].message.content[0]
        test_2 = responsestring[0]
        sorry_test = responsestring[0:9] #This allows us to check if the program refuses to review the input and retry the sent data
        while test_char.isascii() != True and test_2.isascii() != True and sorry_test != "I'm sorry" and sorry_test != "Sorry, I ":
            response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
            )
            responsestring = response.choices[0].message.content
            test_2 = responsestring[0]
            sorry_test = responsestring[0:9]
            test_char = response.choices[0].message.content[0]   
        return response.choices[0].message.content

#class made to deal with printing the disassembly
class DisassemblyPrinter(ida_kernwin.action_handler_t):
    
    #initializing constructor
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    #used to process selected disassembly, and print it to the user
    #main/important functionality
    def activate(self, ctx):
        #check if there is a selection in the current view
        selection = ida_kernwin.read_range_selection(None)
        
        #confirms the selection
        if selection and selection[0]:
            _, start_ea, end_ea = selection
            
            #initialize disassembly list
            disasm_text = []
            ea = start_ea
            
            #iterate over each instruction within the selected range
            #ensures valid instructions are being taken in
            while ea <= end_ea and ea != ida_idaapi.BADADDR:
                #generates the selected line and processes it if valid
                disasm_line = ida_lines.generate_disasm_line(ea, 0)
                if disasm_line:

                    #cleaning the color coding
                    cleaned_line = ida_lines.tag_remove(disasm_line)

                    #retrieve the segment object for the current address
                    seg = ida_segment.getseg(ea)
                    #need modifcation to ensure we are actually getting a valid segment
                    if seg is not None:
                        seg_name = ida_segment.get_segm_name(seg)
                    else:
                        seg_name = "<unknown segment>"

                    #format line to include the segment name and address
                    formatted_line = "{}:{:08X}: {}".format(seg_name, ea, cleaned_line)

                    #adds the cleaned/prepared line to the disassembly list
                    disasm_text.append(formatted_line)

                #go to the next instruction line
                ea = ida_bytes.next_head(ea, end_ea + 1)
            
            #after processing the disassembly, print the cleaned up lines
            f = open("prompt.txt", "w")
            if disasm_text:
                print("Highlighted Disassembly:")
                for line in disasm_text:
                    f.write(line)
                f.close()
                with open("prompt.txt", 'r') as file:
                    lines = file.readlines()
                    prompt = ', '.join(lines)
                result = query(prompt)
                print(result)
            # functionality ne
            else:
                #error case
                print("No disassembly lines were generated for the selection.")    
            return 1
        else:
            #when nothing is selected yfm?
            print("No code selected.")
            return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

#used to define an plugin action for IDA Pro
#   1.action ID
#   2.action name
#   3.function handleer, in this case the disassembly
#   4.no shortcut
#   5.tooltip
#   6.Icon ID
action_desc = ida_kernwin.action_desc_t(
    'my:printdisassembly',
    'Crimson',
    DisassemblyPrinter(),
    None,
    'Print selected disassembly',
    -1)

#registers the action for IDA Pro
ida_kernwin.register_action(action_desc)

#places the plugin/action into the actual menu which is fucking hype
#   1.specifies the path
#   2.the action ID/name
#   3.sets the position of the action within the menu
ida_kernwin.attach_action_to_menu(
    'Edit/Plugins/',       
    'my:printdisassembly',
    ida_kernwin.SETMENU_APP)

#tells the user how to see the disassembly they highlighted
print("Disassembly printer script loaded. Use Edit > Plugins > Crimson to ask for help.")

