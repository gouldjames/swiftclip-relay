# SwiftClip Relay

The web page for SwiftClip's OneDrive relay: it shows items sent from SwiftClip on a Mac, iPhone or iPad, and sends text back, for computers where SwiftClip can't be installed.

Published with GitHub Pages at https://gouldjames.github.io/swiftclip-relay/.

Everything is encrypted and decrypted in the browser with the relay key shown in SwiftClip's settings; OneDrive only stores ciphertext. The page has no server and no third-party code, and talks only to Microsoft sign-in and Microsoft Graph.

This repository holds only the published page. It's a copy of `Web/` from SwiftClip's own repository, where it's developed and tested; `config.js` holds the Microsoft Entra application (client) ID, which isn't a secret.
