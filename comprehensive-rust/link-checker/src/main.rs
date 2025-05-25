use clap::{Parser, ValueEnum};
use reqwest::blocking::Client;
use reqwest::Url;
use scraper::{Html, Selector};
use thiserror::Error;

use std::collections::{HashSet, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    url: String,

    #[clap(short, long, value_enum)]
    implementation: Implementation,

    #[clap(short, long, default_value_t = 10)]
    depth: usize,
}

#[derive(Parser, ValueEnum, Clone, Copy)]
enum Implementation {
    SingleThreaded,
    MultiThreaded,
}

#[derive(Error, Debug)]
enum Error {
    #[error("request error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("bad http response: {0}")]
    BadResponse(String),
}

fn visit_page(client: &Client, url: &Url) -> Result<Vec<Url>, Error> {
    let response = client.get(url.clone()).send()?;
    if !response.status().is_success() {
        return Err(Error::BadResponse(response.status().to_string()));
    }

    let mut link_urls = Vec::new();

    let base_url = response.url().to_owned();
    let body_text = response.text()?;
    let document = Html::parse_document(&body_text);

    let selector = Selector::parse("a").unwrap();
    let href_values = document
        .select(&selector)
        .filter_map(|element| element.value().attr("href"));
    for href in href_values {
        match base_url.join(href) {
            Ok(link_url) => {
                link_urls.push(link_url);
            }
            Err(err) => {
                println!("On {base_url:#}: ignored unparsable {href:?}: {err}");
            }
        }
    }
    Ok(link_urls)
}

trait WebCrawler {
    fn crawl(&mut self, depth: Option<usize>) -> Vec<Url>;
}

#[derive(Debug)]
struct SingleThreadedWebCrawler {
    base_url: Url,
    pending: VecDeque<Url>,
    visited: HashSet<Url>,
}

impl SingleThreadedWebCrawler {
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url: base_url.clone(),
            pending: VecDeque::from([base_url]),
            visited: HashSet::new(),
        }
    }
}

impl WebCrawler for SingleThreadedWebCrawler {
    fn crawl(&mut self, depth: Option<usize>) -> Vec<Url> {
        let depth = depth.unwrap_or(30);
        let client = Client::new();

        while let Some(url) = self.pending.pop_front() {
            if self.visited.len() > depth {
                break;
            }

            let links: Vec<_> = match visit_page(&client, &url) {
                Ok(links) => links,
                Err(err) => {
                    println!("Could not extract links: {err:#}");
                    continue;
                }
            };

            self.visited.insert(url);
            for link in links {
                if !self.visited.contains(&link) {
                    self.pending.push_back(link);
                }
            }
        }

        self.visited.iter().cloned().collect()
    }
}

#[derive(Debug)]
struct MutliThreadedWebCrawler {
    base_url: Url,
    rx: Receiver<Vec<Url>>,
    tx: Sender<Vec<Url>>,
    visited: HashSet<Url>,
}

impl MutliThreadedWebCrawler {
    pub fn new(base_url: Url) -> Self {
        let (tx, rx) = channel();
        Self {
            base_url,
            rx,
            tx,
            visited: HashSet::new(),
        }
    }

    pub fn chunkate(urls: Vec<Url>, chunk_size: usize) -> Vec<Vec<Url>> {
        let mut chunks = Vec::new();
        let mut chunk = Vec::with_capacity(chunk_size);

        for url in urls {
            chunk.push(url);
            if chunk.len() == chunk_size {
                chunks.push(std::mem::take(&mut chunk));
                chunk = Vec::with_capacity(chunk_size);
            }
        }

        if !chunk.is_empty() {
            chunks.push(chunk);
        }

        chunks
    }
}

impl WebCrawler for MutliThreadedWebCrawler {
    fn crawl(&mut self, depth: Option<usize>) -> Vec<Url> {
        let depth = depth.unwrap_or(30);

        'outer: loop {
            match self.rx.try_recv() {
                Ok(urls) => {
                    let urls: Vec<_> = urls
                        .into_iter()
                        .filter(|url| !self.visited.contains(url))
                        .collect();
                    let chunks = Self::chunkate(urls, 10);

                    for chunk in chunks {
                        if self.visited.len() > depth {
                            break 'outer;
                        }
                        std::thread::scope(|s| {
                            for url in chunk {
                                self.visited.insert(url.clone());
                                let tx_clone = self.tx.clone();

                                s.spawn(move || {
                                    match visit_page(&Client::new(), &url) {
                                        Ok(links) => tx_clone.send(links).unwrap(),
                                        Err(err) => {
                                            println!("Could not extract links: {err:#}");
                                        }
                                    };
                                });
                            }
                        });
                    }
                }
                Err(TryRecvError::Empty) => {
                    if self.visited.is_empty() {
                        match visit_page(&Client::new(), &self.base_url) {
                            Ok(links) => {
                                self.visited.insert(self.base_url.clone());
                                self.tx.send(links).unwrap();
                            }
                            Err(err) => {
                                println!("Could not extract base url: {err:#}");
                                break;
                            }
                        };
                    }
                }
                Err(TryRecvError::Disconnected) => break,
            }
        }

        self.visited.iter().cloned().collect()
    }
}

fn main() {
    let args = Args::parse();

    let url = Url::parse(&args.url).unwrap();
    let depth = args.depth;

    let links = match args.implementation {
        Implementation::SingleThreaded => {
            let mut crawler = SingleThreadedWebCrawler::new(url);
            crawler.crawl(Some(depth))
        }
        Implementation::MultiThreaded => {
            let mut crawler = MutliThreadedWebCrawler::new(url);
            crawler.crawl(Some(depth))
        }
    };

    println!("crawled {}", links.len());
}
