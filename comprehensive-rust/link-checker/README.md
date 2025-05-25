## Problem Statement
In this exercise, we want to create a multi-threaded web crawler. It should start at a webpage and check that links on the page are valid. It should recursively check other pages on the same domain and keep doing this until all pages have been validated.


__Multi-threading requirements__

* Use threads to check the links in parallel: send the URLs to be checked to a channel and let a few threads check the URLs in parallel.
* Extend this to recursively extract links from all pages on the www.google.org domain. Put an upper limit of 100 pages or so so that you don’t end up being blocked by the site.


---

*\*Note: [link to problem](https://google.github.io/comprehensive-rust/concurrency/sync-exercises/link-checker.html)* 
