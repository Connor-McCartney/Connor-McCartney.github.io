<br>

As much as I hate Windows, I'm bored so gonna try write a simple DLL. 


<br>


First, I installed Visual Studio Installer and blah blah get the MSVC compiler. 

<br>

I tried developer cmd and it was showing some PATH error so I deleted some stuff from path and that seemed to fix it. 

<br>

Now I can open developer powershell for windows and have access to cl command to compile. 

<br>

<img width="748" height="365" alt="image" src="https://github.com/user-attachments/assets/6afe66a0-4c0b-416c-858f-c51f259046c0" />


<br>

<br>

<br>

<br>

Hello world sanity check:



<br>


<img width="1638" height="352" alt="image" src="https://github.com/user-attachments/assets/2361f85f-9b0a-413e-b6d1-e2b1ce202a22" />



<br>


<br>


<br>

<br>






/LD tells the compiler to output a DLL instead of an exe


<br>


You can compile with a .lib at compile time, or link at runtime using Explicit Linking (aka Dynamic Loading)



