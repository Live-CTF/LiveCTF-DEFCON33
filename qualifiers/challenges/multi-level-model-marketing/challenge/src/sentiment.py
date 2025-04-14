#!/usr/bin/env python3
import sys
import os
import io
import json
from contextlib import redirect_stdout, redirect_stderr
from nltk.sentiment.vader import SentimentIntensityAnalyzer
import nltk
from nltk.corpus import wordnet
import string

NLTK_DATA_DIR = os.getcwd() + '/data'
CACHE_FILE = '/tmp/sentiment_cache.json'

# Download required data silently (first time only)
try:
    nltk.data.path.append(NLTK_DATA_DIR)
    if __name__ != "__main__":
        nltk.data.find('vader_lexicon')
        nltk.data.find('wordnet')
except LookupError:
    # Redirect stdout and stderr to suppress download messages
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        nltk.download('vader_lexicon', quiet=True, download_dir=NLTK_DATA_DIR)
        nltk.download('wordnet', quiet=True, download_dir=NLTK_DATA_DIR)

def get_word_similarity(word1, word2):
    """Calculate semantic similarity between two words using WordNet."""
    # Clean words - remove punctuation and convert to lowercase
    word1 = word1.lower().strip(string.punctuation)
    word2 = word2.lower().strip(string.punctuation)
    
    # If exact match or empty strings, return maximum similarity
    if word1 == word2 or not word1 or not word2:
        return 1.0
    
    # Check for common root or stem (stronger penalty than just semantic similarity)
    min_len = min(len(word1), len(word2))
    if min_len > 3:  # Only check if words are long enough
        common_prefix_len = 0
        for i in range(min_len):
            if word1[i] == word2[i]:
                common_prefix_len += 1
            else:
                break
        
        # If words share more than 60% of their letters as a prefix, consider them very similar
        if common_prefix_len >= min_len * 0.6:
            return 0.8  # High similarity for words with same root
    
    # Get WordNet synsets for both words
    synsets1 = wordnet.synsets(word1)
    synsets2 = wordnet.synsets(word2)
    
    # If no synsets found, return minimum similarity
    if not synsets1 or not synsets2:
        return 0.0
    
    # Calculate maximum similarity between any synset pair
    max_sim = 0.0
    for syn1 in synsets1:
        for syn2 in synsets2:
            sim = syn1.path_similarity(syn2)
            if sim and sim > max_sim:
                max_sim = sim
    
    # Boost the similarity score to emphasize even slight semantic relationships
    return max_sim * 1.2 if max_sim < 0.8 else max_sim

def analyze_sentiment(words):
    # Initialize the sentiment analyzer
    sid = SentimentIntensityAnalyzer() # 'data/sentiment/vader_lexicon.zip'
    
    # Calculate similarity penalties for repeated semantic meaning
    similarity_matrix = []
    highest_similarity = 0
    most_similar_pair = None
    
    for i, word1 in enumerate(words):
        for j, word2 in enumerate(words[:i]):  # Compare with previous words
            similarity = get_word_similarity(word1, word2)
            similarity_matrix.append(similarity)
            
            # Track the most similar word pair for severe penalties
            if similarity > highest_similarity:
                highest_similarity = similarity
                most_similar_pair = (word1, word2)
    
    # Apply exponential penalty for high similarity (penalize more severely)
    if similarity_matrix:
        # Average similarity across word pairs (higher means more repetition)
        avg_similarity = sum(similarity_matrix) / len(similarity_matrix)
        
        # Square the average similarity to severely penalize repetition
        squared_penalty = avg_similarity * avg_similarity
        
        # Add extra penalty for extremely similar words (if found)
        if highest_similarity > 0.7:
            max_similarity_penalty = highest_similarity * 0.2  # Additional penalty for very similar words
        else:
            max_similarity_penalty = 0
        
        # Diversity factor (1.0 for completely diverse words, much lower for similar words)
        diversity_factor = 1.0 - (squared_penalty * 0.9) - max_similarity_penalty
    else:
        diversity_factor = 1.0  # No penalty if no comparisons made
    
    # Join words into a single string for analysis
    text = ' '.join(words)
    
    # Get sentiment scores
    scores = sid.polarity_scores(text)
    
    # Apply diversity factor to compound score
    adjusted_compound = scores['compound'] * diversity_factor
    
    # Convert adjusted score (-1 to 1) to 0-100 scale
    normalized_score = int((adjusted_compound + 1) * 50)
    
    # Ensure score is between 0 and 100
    normalized_score = max(0, min(100, normalized_score))
    
    return normalized_score

def load_cache():
    """Load the sentiment score cache from file if it exists."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            # If there's an error reading the cache, start fresh
            return {}
    return {}

def save_cache(cache):
    """Save the sentiment score cache to file."""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except IOError:
        # If we can't write to the cache file, just continue without caching
        pass

if __name__ == "__main__":
    # Check if we have the right number of arguments
    if len(sys.argv) != 6:
        print("Error: Please provide exactly five words as arguments.")
        print("Usage: python sentiment.py word1 word2 word3 word4 word5")
        sys.exit(1)
    
    # Get words from command line arguments
    words = sys.argv[1:6]
    
    # Create a cache key from the sorted words to handle different order
    cache_key = ':'.join(sorted(words))
    
    # Try to get the score from cache
    cache = load_cache()
    if cache_key in cache:
        print(cache[cache_key])
    else:
        # Calculate sentiment score
        score = analyze_sentiment(words)
        
        # Cache the result
        cache[cache_key] = score
        save_cache(cache)
        
        # Output the score
        print(score)
