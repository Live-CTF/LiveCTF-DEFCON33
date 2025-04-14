This folder structure is a template for a CTF challenge. 

The challenge is called Multi-Level Model Marketing. It should be a C application that interacts with standard in and
out and has a menu structure that let people play a game pretending to be a MLMM. It simulates a single-player
turn-based game in which players pretend to be a multi-level marketing model that must get the highest revenue over time
with the following gameplay elements

##  Game Mechanics
 - [x] Multi-tier recruit system (recruit downlines, gain % of their success)
 - [x] Dynamic market simulation (change effectiveness of keywords over time)
 - [x] Random event system (e.g., "Regulatory crackdown", "Viral success", etc.)
 - [x] Daily news feed (flavor text + hint for effective ads)
 - [x] Region targeting (run ads in different markets with different demographics)
 - [x] Fraud detection system (penalties for keyword stuffing or spammy behavior)
 - [x] Product line management (ads tied to specific fake products)
 - [x] Inventory system for promotional materials
 - [x] Legal risk score (increases with shady practices, game over if too high)

## Player Actions
 - [x] Hire and fire sales agents
 - [x] Train agents (costs money, increases sales effectiveness)
 - [x] Create custom ad campaigns (combine multiple keywords)
 - [x] Pause/resume campaigns
 - [x] Set ad budget per round
 - [ ] Buy competitor intelligence
 - [ ] Spy on top-performing players (simulated)
 - [ ] Conduct PR campaign to fix bad reputation
 - [ ] Get loans or investments
 - [ ] Bribe influencers for success boosts

## Scoring/Progress
 - [x] Reputation score (impacts success rate)
 - [x] MLM rank/tier system (Bronze, Silver, Gold, Diamond, etc.)
 - [x] Daily/round summary report
 - [x] Graph-based downline tracking
 - [x] High Score win

## Classifier/NLP Integration
 - [ ] Prompt generation system using keywords
 - [x] Sentiment analysis of ad copy
 - [ ] Predict success of ads using trained model
 - [ ] Extract keywords from generated ad copy
 - [ ] Compare player's ad quality to simulated competitor

## UI/UX
 - [x] Menu system with nested choices
 - [x] Help menu for each section
 - [x] ASCII-art intro screen (lol, AI is hilarious)
 - [x] Save/load game state
 - [x] Input validation utilities

## Technical/Utility
 - [x] Debug/debug mode with hidden stats
 - [x] Modular RNG for events
 - [x] Configurable difficulty settings
 - [x] Easter eggs (hidden menu, fake endings)
