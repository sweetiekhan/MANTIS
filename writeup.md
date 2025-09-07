# Writeup 

<b> 
I was reverse-engineering a simple software.

This software had a version that provided free service for one week.

<i> 
While testing the program, I realized that no requests were being sent from the program to generate a license. After several attempts, I discovered that the program saves a random code along with the date and time in a file located at C:\Users\{nameLogin}\AppData in txt format</i>

In other words, it validated the license and its expiration directly from this file.

Using the Mantis tool, I found that when the program runs, a file is created in this path! So, I decided to release this program for free for you! If you want to add new features to this program, send me a message on Telegram or report it on GitHub.b</b> 
