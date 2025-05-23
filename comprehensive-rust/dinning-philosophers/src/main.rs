#![allow(dead_code)]

use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
struct Chopstick;

#[derive(Debug)]
struct Philosopher {
    name: String,
    left_chopstick: Arc<Mutex<Chopstick>>,
    right_chopstick: Arc<Mutex<Chopstick>>,
    thoughts: mpsc::Sender<String>,
}

impl Philosopher {
    fn new(
        name: impl Into<String>,
        left_chopstick: Arc<Mutex<Chopstick>>,
        right_chopstick: Arc<Mutex<Chopstick>>,
        thoughts: mpsc::Sender<String>,
    ) -> Self {
        Self {
            name: name.into(),
            left_chopstick,
            right_chopstick,
            thoughts,
        }
    }

    fn think(&self) {
        self.thoughts
            .send(format!("Eureka! {} has a new idea!", &self.name))
            .unwrap();
    }

    fn eat(&self) {
        // Pick up chopsticks...
        let _l_ch = self.left_chopstick.lock().unwrap();
        let _r_ch = self.right_chopstick.lock().unwrap();
        println!("{} is eating...", &self.name);
        thread::sleep(Duration::from_millis(10));
    }
}

static PHILOSOPHERS: &[&str] = &["Socrates", "Hypatia", "Plato", "Aristotle", "Pythagoras"];

fn main() {
    let (tx, rx) = mpsc::channel();
    let num_of_philosophers = PHILOSOPHERS.len();

    // Create chopsticks
    let chopsticks: Vec<_> = (0..num_of_philosophers)
        .map(|_| Arc::new(Mutex::new(Chopstick)))
        .collect();

    // Create philosophers
    // The 'chainned' philosopher's chopsticks are inverted to prevent deadlock
    let philosophers: Vec<_> = chopsticks
        .windows(2)
        .enumerate()
        .map(|(i, w)| Philosopher::new(PHILOSOPHERS[i], w[0].clone(), w[1].clone(), tx.clone()))
        .chain([Philosopher::new(
            PHILOSOPHERS[num_of_philosophers - 1],
            chopsticks[0].clone(),
            chopsticks[num_of_philosophers - 1].clone(),
            tx.clone(),
        )])
        .collect();

    // Make each of them think and eat 100 times
    for philosopher in philosophers {
        thread::spawn(move || {
            for _ in 0..100 {
                philosopher.think();
                philosopher.eat();
            }
        });
    }

    // Output their thoughts
    let thoughts_th = thread::spawn(move || {
        let mut thoughts = Vec::new();

        while let Ok(thought) = rx.recv() {
            thoughts.push(thought);
        }

        thoughts
    });

    drop(tx);
    let thoughts = thoughts_th.join().unwrap();

    assert_eq!(thoughts.len(), num_of_philosophers * 100);
}
