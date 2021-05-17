---
layout: post
title: Hacking fingerprints
categories: Misc
---


One of my favorite tv shows ever is Mr Robot. It is commonly praised for its remarkably realistic hacks. But despite my eternal love for it, and the realism of a lot of the hacks, I had many questions when I did my 4th rewatch of the series. In S4E5, Darlene and Elliot break into Virtual Realty. Through a combination of social engineering, and technical attacks on physical security systems, they get into the server room. Most of this was done in the 40 minutes that their hack on the security cameras allowed them.

A lot of things had to go exactly right, and I felt it was time to either prove or debunk parts of this hack. I'm not the first to analyse this hack. [Vice](https://www.vice.com/en/article/vb58mx/a-roundtable-of-hackers-dissects-mr-robot-season-4-episode-5-method-not-allowed) has analyzed many parts of it. [A thread on Reddit](https://www.reddit.com/r/MrRobot/comments/dy8br6/plausibility_of_the_fingerprint_hack_in_4x05/) showed some doubts about the fingerprint hack. But a similar attack [has been pulled off](https://www.theverge.com/2019/4/7/18299366/samsung-galaxy-s10-fingerprint-sensor-fooled-3d-printed-fingerprint) before.

My main doubts are as follows.

- 40 minutes seems like too little time, even with prep.
- Going for a full-on social engineering attack is bold, even for Elliot and Darlene.
- What kind of putty was used? Did Elliot and Darlene know what type of scanner there would be?

Other remarks that I will not be following up on are: (Please do investigate, if you have the time)

- The print had a lot of detail. Could that printer handle that? if so, how long should that print take?
- The mold they printed was big and concave. What is the reason for that?

## Types

Common types of scanners I've come across online are:

- optical
- capacitive
- ultrasonic

We don't get a good look at the scanners surface. It is not unlikely that it is of the optical variety, as this technology has been in use for quite long. More modern scanners are capacitive, like in my phone and laptop. Ultrasonic scanners are popping up more and more, as this technology can be hidden underneath smartphone screens.

## Mold

To make my mold, I took the following steps.

First of all, I made a scan of my fingerprint. To give myself the best chance, I applied ink to my index finger and placed it on some paper. Be liberal with ink, and don't apply too much pressure or details might get lost. I scanned with 600 dpi in color.

I then took this image, and used paint dot net to extract just the print. The easiest way to do so is by cropping and resizing to smaller than 1000*1000 pixels, then converting to grayscale and then adjusting the curves so the image is black and white with all the important ridges, and without any noise where the ridges are not.

I do not know yet if it is more important to get all the ridges, or if it is more important to get rid of all the noise.

The 1000*1000 pixel limit is because of a limitation in TinkerCAD, which will be used later on in the process.

Take the extracted fingerprint, and import it in gimp. Select all the white, invert, and make a path from this selection. Then enable the path window, right click on this path, and export it as an svg file.

Import the svg in a new tinkercad project. Make sure it's a private one.

Do not forget to invert the model where necessary. (this might be more complicated than I first realized. Consider not inverting the selection in Gimp; inverting the print by pulling one corner over the other; or using the imported fingerprint as additive, or as a hole inside a block.)

I printed the mold on an Anet 8A plus, with 123-3d Jupiter black PLA. The print was made with a .06 mm resolution, 210 degree extruder, 60 degree bed, with the fan at 100%. No adhesion had to be printed. The print took 1 hour and 22 minutes.

## Material

My laptop and phone both use capacitive sensors. Breathing at my phone's activates it. Hot glue on the other hand, does not. So there goes my material of choice.

After hot glue, I considered a mixture of flour and water. Don't judge me, it was Sunday night and I didn't have many options. To everyones surprise, it was a huge failure. It was too sticky and too elastic to maintain the print. It did manage to activate the sensor, so my theory of 'it activates when water' held up.

The next day I went to the supermarket, and picked up some chewing gum and putty. First of all, I tested each for their capacitive characteristics. While they both activated the phones sensor, the putty didn't do a great job. It only worked if I pressed it hard onto the phones sensor and on the laptop it didn't work at all. Grabbing the print from the mold and using that on the phone was unsuccessful.

Seeing how the pressure affected the 'saved' print, It is doubtful that having a full mold of the finger would help. As opposed to just a 2d rectangle with the print pressed into it. To get enough of the surface onto the scanner, a lot of pressure would have to be applied that the center would start losing a lot of detail.

The chewing gum was even worse. While it did do a better job at being detected, it was too sticky and too stretchy to keep the print.

## Conclusion

While we haven't managed to break into a phone or laptop, I still consider this research a success. We've all but debunked at least the timeline in Mr Robot. I hope this post also inspires you to continue this research.

## what other people say

More context on the episode: <https://www.forbes.com/sites/kateoflahertyuk/2019/11/04/mr-robot-season-4-episode-5-a-spectacular-hack-in-three-parts/>

Praise for this episode as realistic: <https://www.spoilertv.com/2019/11/mr-robot-405-not-found-review.html>
