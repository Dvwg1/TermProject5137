CrimsonBehelit

Description:
This script is a tool meant to allow analysts to select dissassembly code from a decompiled 
executable in IDA Pro. The script will then produce a plugin named Crimson, that when ran
will print out an analysis of the assembly by a ChatGPT 3.5-turbo API. This tool is meant
to be used as an aid for static analysis. 

Environment/Setup:
This will work in any architecture, whether it be Linux, MacOS, or Windows. The needed
module is g4f, which can be installed via the following command:

pip install -U g4f

Important Note:
During initial devlopment and testing, one of our machines ran into an issue with IDA python
plugins, and would not run the script. This required a fresh re-install of IDA Pro. During 
testing, if IDA python plugin errors occur, it may need to be freshly re-installed.

Occasionally when the script runs you will get a message that says "IDA is not responding". 
If you click wait, the script will load the response from ChatGPT.

Rarely ChatGPT will respond with "Sorry, I can't assist with that". If you resend the 
highlighted code it should process correctly. 

Additionally, gpt4f module could, due to its nature, at any given point
cease to function due to its legally ambiguous nature. We have no control over this, and we
believe that the module should still be functional for testing. As of submission, this Python
module is still functioning and working as expected/intended.

Finally, in order to handle multiple lines of highlighted code, this program requires the ability 
to open and write to a file. This stores the query and is then opened and read in order to send to ChatGPT.

Instructions:
1. Load an executable to be analysed statically into IDA Pro.
2. Go to: 
   
   File > Script File > {Download Location}/CrimsonBehelit.py

3. Go to the assembly view of the executable, and highlight a section of code or function
   that you are interested in having analysed. If nothing is selected, you will be told
   to select something during analysis
4. In the Python output, you will be provided with the following instructionsm on how to
   open the custom pluing named "Crimson"

   Disassembly printer script loaded. Use Edit > Plugins > Crimson to ask for help.

5. Upon running the Crimson plugin, due to the nature of the script, the time to produce
   an analysis may be slow (up to 30 seconds) due to latency issues. 
6. From here, you can continue to highlight code/functions, and use the plugin to produce
   an analysis
