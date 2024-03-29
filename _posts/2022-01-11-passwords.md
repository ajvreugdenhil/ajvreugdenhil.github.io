---
layout: post
title: Making strong passwords
categories: [Introduction, General security]
published: true
last_modified_at: 2023-04-29
excerpt_separator: <!--more-->
---

Everyone knows that they should use strong passwords. The chance of getting compromised through a weak or exposed password is small, but the implications for your (digital) life could be painful. Sadly, picking strong passwords might not be intuitive. And since I can't go around asking everyone around me to tell me their passwords to judge whether they're good or not, the best I can do is write a guide to avoid common mistakes.

The TL;DR here is to use a password manager and use passwords based on fully random data like a die or a trustworthy random number generator.

## Background

An attacker might obtain your password in one of a few ways like password cracking after an organization has been hacked and password hashes have been leaked, or through phishing where the attacker targets the individual directly.

<!--more-->

### Password cracking

Attackers have limited resources. That means that they can only crack the weakest portion of the leaked hashes. That is, assuming the service implements best practices like hashing. This process uses one-way maths. When you log in, your password is verified only by comparing the result of the equation to the result of the equation that was stored when you made or changed your password. An attacker would have to try many options before knowing which one matches.

There are two ways passwords are cracked. One is cracking with brute force, and the other is by generating potential matches using patterns. This is either done on-the-fly or by making a 'dictionary' in advance.

Brute force attacks are simple. The attacker tries everything from 'a' through 'ZZZZZZZZZZZZ', including all lower- and uppercase letters, numbers, a limited amount of symbols or whichever combination the attacker thinks is likely to work.

Dictionary attacks are an art. The attacker may try combinations of common names, seasons, years, and limited permutations on all. This may include an uppercase letter as the first character, and an exclamation point as a last character.

### A hack can be permanent

When an account is hacked, an attacker may change the email address, change the password or enable MFA on the account. This means that you can no longer access the account. Not all companies will respond to support requests and the police are almost never of help. This means that you could permanently lose access to the account and the data inside it!

## Don'ts

Don't use weak passwords. This includes

- known ones (Love, password, 1234567, Welcome01!);
- easily guessable ones (fikkie, [maga2020!](https://www.washingtonpost.com/world/2020/12/17/dutch-trump-twitter-password-hack/));
- generatable ones (8September1999);
- keyboard walks.

Keyboard walks are sequences of letters or characters that follow a path over your physical keyboard like `qwertyuiop` or `qazwsxedc`. These are not random and everyone shares the same keyboard layouts so they are easily guessed.

There is no rule against using a capital letter for the first letter or adding a punctuation mark at the end but this does not increase security as much as you might think.

Don't use pen and paper. Your passwords are unlikely to get stolen, and on paper (haha) this is not a bad idea. But this approach increases the barrier to use strong passwords, but it also makes it more likely that you'll reuse passwords. If you ignore this advice, do not store them along your laptop, on a sticky note under your keyboard, or anywhere untrusted people can access it.

While using a password system like `mypassword-PC`, `mypassword-SocialMedia`, `mypassword-Email` is __technically__ better than using the exact same password for all accounts, this is still not a good practice. When one leaks, an attacker can still use it to get into the other accounts.

## Do's

Use a password manager. There are good ones that can be used for free. Just make sure that like with any service you use, the company has a good business model.

You will still need a few memorable passwords. Like for your computer, your password manager and the encryption key to your backups. (You do have backups, right?)

Use a passphrase, consisting of many (at least 6) words. Join them together with spaces, dashes, slashes, or other characters. If you need help choosing words (you probably do), [Diceware](https://theworld.com/~reinhold/diceware.html) may help. [This](https://www.rempe.us/diceware/#eff) is an easier to use alternative.

Learn all passwords by heart immediately. And keep using them. Often times, you cannot recover the master password to your password manager. By regularly typing in your password, you make sure not to forget it. If you can store it in a safe place, it is not necessarily a bad idea to write down your master password.

Use a unique password for all the accounts you care about. It might not matter to you if a game account of 6 years ago is compromised, but if someone uses that same password to get into your email account, you're in big trouble.

## Final words

Use MFA (multi factor authentication) to authenticate with not only something you know (your password) but also something you have (a keyfob or your phone). There are free authenticator apps available. This helps more than an increase in password strength can.

You might want to plug your email address(es) into [Have I been Pwned](https://haveibeenpwned.com/). This service tells you if your account has been in a breach. If an account has been, make sure all passwords that match that accounts password are changed as soon as possible.
