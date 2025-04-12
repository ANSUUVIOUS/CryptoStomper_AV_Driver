# PowerGuard Driver

This driver is necessary for the PowerGuard Plugin to perform it's operation due to requiring Kernel Mode Access for discovery of processes, getting process memory locations, along with killing processes when necessary. In order to install this driver, please use the [OSRLoader APP](https://www.osronline.com/article.cfm%5Earticle=157.htm) - the driver needs to get driver signatures from Microsoft in order for it to be installed without **testsigning mode** being **on** in Windows. 

Please see this instruction manual on how to enable test signing in Windows: https://www.apriorit.com/dev-blog/kernel-driver-debugging-with-windbg
