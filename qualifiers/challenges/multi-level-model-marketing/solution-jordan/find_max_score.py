#!/usr/bin/env python3
import subprocess
import random
import nltk
from nltk.sentiment.vader import SentimentIntensityAnalyzer
import io
from contextlib import redirect_stdout, redirect_stderr

# Download required data silently (first time only)
try:
    nltk.data.find('vader_lexicon')
except LookupError:
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        nltk.download('vader_lexicon', quiet=True)

# Initialize the sentiment analyzer to get positive words
sid = SentimentIntensityAnalyzer()

def get_real_score(words):
    """Run the actual sentiment.py script to get the score"""
    try:
        word_list = list(words) if isinstance(words, tuple) else words
        result = subprocess.run(
            ["python3", "sentiment.py"] + word_list, 
            capture_output=True, 
            text=True,
            check=True
        )
        return int(result.stdout.strip())
    except (subprocess.CalledProcessError, ValueError):
        return 0

def get_top_positive_words(n=200):
    """Get the top n positive words from VADER lexicon"""
    positive_words = []
    for word, score in sid.lexicon.items():
        if score > 0.6 and len(word) > 2 and '_' not in word:
            positive_words.append((word, score))
    
    # Sort by score in descending order
    positive_words.sort(key=lambda x: x[1], reverse=True)
    return [word for word, _ in positive_words[:n]]

def random_walk_search(max_iterations=100):
    """Use random walks to find high-scoring combinations"""
    # Start with a set of high-scoring candidate words
    initial_candidates = [
        # Known high-scoring words from previous tests
        "joy", "miracle", "success", "wonderful", "excellent",
        "perfect", "ideal", "magnificent", "euphoric", "jubilant",
        "triumph", "breathtaking", "brilliant", "ecstatic", "healing",
        "masterpiece", "fantastic", "nurturing", "phenomenal", "superb",
        "happiness", "delightful", "love", "amazing", "outstanding",
        "victorious", "glorious", "exhilarating", "blissful", "revolutionizing",
        # Add more candidates from VADER
    ]
    
    # Add more candidates from VADER lexicon
    top_words = get_top_positive_words(100)
    all_candidates = list(set(initial_candidates + top_words))
    print(f"Starting with {len(all_candidates)} candidate words")
    
    # Start with some known good combinations
    best_combinations = [
        ["joy", "miracle", "success", "wonderful", "excellent"],
        ["perfect", "ideal", "ecstatic", "euphoric", "jubilant"],
        ["excellent", "triumph", "healing", "breathtaking", "nurturing"]
    ]
    
    # Find initial scores for these combinations
    best_score = 0
    best_combo = None
    for combo in best_combinations:
        score = get_real_score(combo)
        print(f"Initial combination {combo} scored: {score}")
        if score > best_score:
            best_score = score
            best_combo = combo
    
    # Random walk algorithm
    print("\nStarting random walk search...")
    current_combo = best_combo.copy()
    current_score = best_score
    
    for i in range(max_iterations):
        # Generate a neighbor by randomly replacing 1-2 words
        num_replacements = random.randint(1, 2)
        indices_to_replace = random.sample(range(5), num_replacements)
        
        neighbor = current_combo.copy()
        for idx in indices_to_replace:
            # Replace with a random word from candidates
            neighbor[idx] = random.choice(all_candidates)
        
        # Get score for the new combination
        neighbor_score = get_real_score(neighbor)
        print(f"Iteration {i+1}: {neighbor} scored {neighbor_score}")
        
        # If better, move to this combination
        if neighbor_score > current_score:
            current_combo = neighbor
            current_score = neighbor_score
            print(f"Found improvement! New best score: {current_score}")
            
            # Update global best if needed
            if current_score > best_score:
                best_score = current_score
                best_combo = current_combo.copy()
                print(f"NEW GLOBAL BEST: {best_combo} with score {best_score}")
        
        # Sometimes take a step even if not better (to avoid local maxima)
        elif random.random() < 0.1:  # 10% chance to move anyway
            current_combo = neighbor
            current_score = neighbor_score
            print(f"Taking random step to {current_combo} with score {current_score}")
    
    print("\nBEST COMBINATION FOUND:")
    print(f"Words: {best_combo}")
    print(f"Score: {best_score}")
    return best_combo, best_score

if __name__ == "__main__":
    random_walk_search(max_iterations=50)