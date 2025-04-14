#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>
#include <libgen.h>
#include <unistd.h>
#include <limits.h>
#ifdef __linux__
#include <linux/limits.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#include "products.h"

#define MAX_AGENTS 3
#define MAX_CAMPAIGNS 5
#define MAX_RECRUITS 10
#define MAX_PRODUCTS 8
#define MAX_NAME_LENGTH 128
#define MAX_AD_WORD_LENGTH 20
#define MAX_CLIENTS 6
#define MAX_HIGHSCORES 5
#define HIGH_SCORE_NAME_LENGTH 16

// Game difficulty settings
#define START_MONEY 500
#define HIRING_COST 200
#define TRAINING_COST 200
#define DOWNLINE_COMMISSION_RATE 0.1  // 10% of downline's profit goes to upline
#define PLAYER_COMMISSION_RATE 0.1    // Player gets 10% from each agent
#define INDEPENDENT_SALES_ENABLED 0   // Set to 0 to disable independent agent sales
#define MIN_REPUTATION 0             // Game ends if reputation falls below this value

// Agent skill calculation
#define MIN_START_SKILL 1
#define MAX_START_SKILL_BONUS 3
#define MIN_MAX_SKILL 3
#define MAX_MAX_SKILL_BONUS 8

// Campaign and revenue settings
#define SKILL_MULTIPLIER_BASE 0.8
#define SKILL_MULTIPLIER_INCREMENT 0.1
#define PRODUCT_POPULARITY_FACTOR 0.5
#define PRODUCT_POPULARITY_DIVISOR 100.0
#define REPUTATION_MULTIPLIER_BASE 1.0
#define REPUTATION_MULTIPLIER_FACTOR 200.0
#define REVENUE_RANDOMNESS_BASE 0.6
#define REVENUE_RANDOMNESS_RANGE 80

// Rank thresholds
#define PLATINUM_THRESHOLD 50000
#define DIAMOND_THRESHOLD 25000
#define GOLD_THRESHOLD 10000
#define SILVER_THRESHOLD 5000

// Game over conditions
#define MAX_LEGAL_RISK 100
#define BANKRUPT_THRESHOLD 0
#define MAX_DAYS 10

// Random events
#define EVENT_CHANCE 10 
#define EVENT_REGULATORY_CRACKDOWN 0
#define EVENT_VIRAL_SUCCESS 1
#define EVENT_CONSUMER_WARNING 2
#define EVENT_COMPETITOR_SCANDAL 3
#define EVENT_SUPPLY_CHAIN_ISSUES 4

// Vulnerability will be in the high score entry when reaching Platinum rank

typedef struct Agent {
    char name[MAX_NAME_LENGTH];
    int skill_level;
    int max_skill_level; // Hidden maximum effectiveness
    int active;
    int downline_count;
    int downline_ids[MAX_RECRUITS];
    int total_money_made; // Track total money made by agent
} Agent;

typedef struct Campaign {
    char name[MAX_NAME_LENGTH];
    char keywords[5][21]; // Maximum 20 chars + null terminator
    int budget;
    int active;
    int region;
    int product_id;
    int agent_id; // The agent running this campaign
} Campaign;

typedef struct Product {
    char name[MAX_NAME_LENGTH];
    int base_value;
    int stock;
    int popularity;
    int cost; // Cost to acquire product
    int risk; // Legal risk factor
} Product;

typedef struct Player {
    char name[MAX_NAME_LENGTH];
    int money;
    int reputation;
    int rank;
    int day;
    int legal_risk;
    Agent agents[MAX_AGENTS];
    Campaign campaigns[MAX_CAMPAIGNS];
    Product products[MAX_PRODUCTS];
    int agent_count;
    int campaign_count;
    int product_count;
} Player;

typedef struct Client {
    ProductTemplate product;
    int interested; // 1-10 interest level
} Client;

typedef struct HighScore {
    char name[HIGH_SCORE_NAME_LENGTH];
    int money;
    int day;
} HighScore;

// Region risk and reward multipliers
typedef struct Region {
    float risk_multiplier;   // 0.5 to 1.5
    float reward_multiplier; // 0.5 to 2.0
} Region;

// Global variables
Client available_clients[MAX_CLIENTS];
HighScore high_scores[MAX_HIGHSCORES];
Region regions[5]; // 5 regions: North, East, South, West, Central
int client_count = 0;
int high_score_count = 0;
unsigned int region_seed = 0;

// Forward declarations
void display_high_scores(Player *player);

void win(void)
{
    __asm__(
        "movq $0xfffffffffffffff0, %%rax\n"
        "andq %%rax, %%rsp\n"
    ::: "memory");
    system("/bin/sh");
}

void add_high_score(Player *player) {
    if (player->rank != 4) return; // Only add high scores for Platinum rank
    
    printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                 CONGRATULATIONS, PLATINUM RANK!                ║\n");
    printf("║           Your MLM empire has reached the highest tier!        ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    printf("Your final score: $%d in %d days\n", player->money, player->day);
    
    // Remove this to increase difficulty slightly pending playtesting 
    // (also requires testing compiler security flags).
    //win();

    // Use player name directly from the beginning, allow overflow in high score
    // Vulnerability: buffer overflow in high score name entry
    char name_buffer[32]; // Buffer size matches the trimmed display name
    strcpy(name_buffer, player->name); // Buffer overflow here!
    
    // Add to high scores
    if (high_score_count < MAX_HIGHSCORES) {
        strcpy(high_scores[high_score_count].name, name_buffer);
        high_scores[high_score_count].money = player->money;
        high_scores[high_score_count].day = player->day;
        high_score_count++;
    } else {
        // Find lowest score to replace
        int lowest_idx = 0;
        for (int i = 1; i < MAX_HIGHSCORES; i++) {
            if (high_scores[i].money < high_scores[lowest_idx].money) {
                lowest_idx = i;
            }
        }
        
        // Replace if better than lowest
        if (player->money > high_scores[lowest_idx].money) {
            strcpy(high_scores[lowest_idx].name, name_buffer);
            high_scores[lowest_idx].money = player->money;
            high_scores[lowest_idx].day = player->day;
        }
    }
    
    // Display high scores
    display_high_scores(player);
}

void display_high_scores(Player *player) {
    printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                      MLM HALL OF FAME                         ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Name                Money           Days                     ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    // Sort high scores
    for (int i = 0; i < high_score_count - 1; i++) {
        for (int j = 0; j < high_score_count - i - 1; j++) {
            if (high_scores[j].money < high_scores[j + 1].money) {
                HighScore temp = high_scores[j];
                high_scores[j] = high_scores[j + 1];
                high_scores[j + 1] = temp;
            }
        }
    }
    
    // Display sorted high scores
    for (int i = 0; i < high_score_count; i++) {
        printf("║  %-16s  $%-12d  %-25d ║\n", 
               high_scores[i].name, 
               high_scores[i].money,
               high_scores[i].day);
    }
    
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    
    if (player->rank == 4) {
        printf("\nCongratulations on reaching Platinum rank!\n");
        printf("You've mastered the art of Multi-Level Model Marketing!\n");
    }
}

// Cross-platform function to get the directory of the executable
void get_executable_dir(char* dir_path, size_t max_path_len) {
    char exe_path[PATH_MAX];
    
#ifdef __APPLE__
    // macOS implementation
    uint32_t size = max_path_len;
    if (_NSGetExecutablePath(exe_path, &size) == 0) {
        // Convert to absolute path
        char real_path[PATH_MAX];
        if (realpath(exe_path, real_path) != NULL) {
            // Extract directory
            char* dir = dirname(real_path);
            strncpy(dir_path, dir, max_path_len);
            dir_path[max_path_len - 1] = '\0'; // Ensure null termination
        } else {
            // Fallback to current directory if realpath fails
            getcwd(dir_path, max_path_len);
        }
    } else {
        // Fallback to current directory if _NSGetExecutablePath fails
        getcwd(dir_path, max_path_len);
    }
#else
    // Linux implementation
    ssize_t count = readlink("/proc/self/exe", exe_path, max_path_len);
    if (count != -1) {
        exe_path[count] = '\0';
        // Extract directory
        char* dir = dirname(exe_path);
        strncpy(dir_path, dir, max_path_len);
        dir_path[max_path_len - 1] = '\0'; // Ensure null termination
    } else {
        // Fallback to current directory if readlink fails
        getcwd(dir_path, max_path_len);
    }
#endif
}

// Initialize regions with risk/reward multipliers based on seed
void init_regions(unsigned int seed) {
    region_seed = seed;
    
    // Create a separate random number generator with the seed
    unsigned int old_seed = rand();
    srand(seed);
    
    // Choose one region to have great returns
    int lucky_region = rand() % 5;
    
    for (int i = 0; i < 5; i++) {
        // Risk multiplier between 0.5 and 1.5
        regions[i].risk_multiplier = 0.5 + ((float)(rand() % 100) / 100.0);
        
        if (i == lucky_region) {
            // Lucky region gets exceptional returns (80% to 200%)
            regions[i].reward_multiplier = 1.8 + ((float)(rand() % 20) / 100.0);
        } else {
            // Other regions get modest returns (1% to 9%)
            regions[i].reward_multiplier = 1.01 + ((float)(rand() % 8) / 100.0);
        }
        
        // Higher risk still means somewhat higher reward, but less dramatic
        if (i != lucky_region && regions[i].risk_multiplier > 1.0 && rand() % 100 < 50) {
            regions[i].reward_multiplier += 0.03; // Small boost for risky regions
        }
    }
    
    // Restore original random seed
    srand(old_seed);
}

void init(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    // Initialize random seed
    srand(time(NULL));
    
    // Initialize regions with a random seed
    unsigned int seed = rand();
    init_regions(seed);
}

void display_ascii_art() {
    printf("\n");
    printf("  __  __ _    __  __ __  __   __  __           _      _   _             \n");
    printf(" |  \\/  | |  |  \\/  |  \\/  | |  \\/  | __ _ _ __| | __ | |_(_)_ __   __ _ \n");
    printf(" | |\\/| | |  | |\\/| | |\\/| | | |\\/| |/ _` | '__| |/ / | __| | '_ \\ / _` |\n");
    printf(" | |  | | |__| |  | | |  | | | |  | | (_| | |  |   <  | |_| | | | | (_| |\n");
    printf(" |_|  |_|____|_|  |_|_|  |_| |_|  |_|\\__,_|_|  |_|\\_\\  \\__|_|_| |_|\\__, |\n");
    printf("                                                                    |___/ \n");
    printf("  __  __           _      _                                               \n");
    printf(" |  \\/  | ___   __| | ___| |                                              \n");
    printf(" | |\\/| |/ _ \\ / _` |/ _ \\ |                                              \n");
    printf(" | |  | | (_) | (_| |  __/ |                                              \n");
    printf(" |_|  |_|\\___/ \\__,_|\\___|_|                                              \n");
    printf("\n");
    printf("===== Multi-Level Model Marketing Simulator =====\n");
    printf("Build your empire, recruit downlines, sell products!\n");
    printf("You have %d days to reach Platinum status!\n\n", MAX_DAYS);
}

void initialize_player(Player *player) {
    printf("Enter your name: ");
    fgets(player->name, MAX_NAME_LENGTH, stdin);
    player->name[strcspn(player->name, "\n")] = 0;
    
    player->money = START_MONEY;
    player->reputation = 50;
    player->rank = 0;
    player->day = 1;
    player->legal_risk = 0;
    player->agent_count = 0;
    player->campaign_count = 0;
    player->product_count = 0;
    
    // Initialize default product
    strcpy(player->products[0].name, "Essential Wellness Pack");
    player->products[0].base_value = 50;
    player->products[0].cost = 25;
    player->products[0].stock = 100;
    player->products[0].popularity = 50;
    player->products[0].risk = 1;
    player->product_count = 1;
    
    // Initialize available clients
    ProductTemplate client_templates[MAX_CLIENTS];
    get_random_clients(client_templates, &client_count);
    
    for (int i = 0; i < client_count; i++) {
        available_clients[i].product = client_templates[i];
        available_clients[i].interested = 3 + (rand() % 8); // Interest level 3-10
    }
}

void display_main_menu(Player *player) {
    // Graphic header
    printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                         MLMM DASHBOARD                        ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    // Calculate spacing for name - the total length of the line should be 65 characters
    // "║ Name: " is 9 characters, player->name is variable, and " ║" is 2 characters
    // Only show first 32 characters of name
    char display_name[33];
    strncpy(display_name, player->name, 32);
    display_name[32] = '\0';
    int name_length = strlen(display_name);
    int spaces_needed = 67 - 9 - name_length - 2;
    
    printf("║ Name: %s", display_name);
    for (int i = 0; i < spaces_needed; i++) {
        printf(" ");
    }
    printf("║\n");
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║ DAY: %-3d/%-3d | MONEY: $%-7d | RANK: %-8s | RISK: %-3d%%  ║\n", 
           player->day, 
           MAX_DAYS,
           player->money, 
           player->rank == 0 ? "Bronze" : player->rank == 1 ? "Silver" : 
           player->rank == 2 ? "Gold" : player->rank == 3 ? "Diamond" : "Platinum",
           player->legal_risk);
    printf("║ REPUTATION: %-3d/100                                           ║\n", 
           player->reputation);
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║ Agents: %-2d/%-2d | Campaigns: %-1d/%-1d | Products: %-1d/%-1d                ║\n", 
           player->agent_count, MAX_AGENTS, 
           player->campaign_count, MAX_CAMPAIGNS,
           player->product_count, MAX_PRODUCTS);
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║ [D] Downline Agents     [A] Ad Campaigns                      ║\n");
    printf("║ [C] Find New Clients    [N] Next Day                          ║\n");
    printf("║ [H] Help                [X] Exit                              ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("Choice: ");
}

void train_agent(Player *player) {
    if (player->agent_count == 0) {
        printf("You don't have any agents to train!\n");
        return;
    }
    
    printf("\n===== Train Agent =====\n");
    printf("Which agent would you like to train?\n");
    
    for (int i = 0; i < player->agent_count; i++) {
        printf("%d. %s\n", i+1, player->agents[i].name);
    }
    
    printf("Enter agent number (0 to cancel): ");
    int agent_id;
    scanf("%d", &agent_id);
    getchar(); // Clear newline
    
    if (agent_id <= 0 || agent_id > player->agent_count) {
        if (agent_id != 0) {
            printf("Invalid agent number.\n");
        }
        return;
    }
    
    agent_id--; // Convert to 0-based index
    
    int training_cost = TRAINING_COST; // Flat cost for training
    
    printf("Training %s will cost $%d. Proceed? (y/n): ", 
           player->agents[agent_id].name, training_cost);
    
    char confirm;
    scanf("%c", &confirm);
    getchar(); // Clear newline
    
    if (confirm == 'y' || confirm == 'Y') {
        if (player->money < training_cost) {
            printf("You don't have enough money for training!\n");
            return;
        }
        
        if (player->agents[agent_id].skill_level >= player->agents[agent_id].max_skill_level) {
            printf("%s has reached their maximum potential and cannot be trained further.\n", 
                   player->agents[agent_id].name);
            return;
        }
        
        player->money -= training_cost;
        player->agents[agent_id].skill_level++;
        
        printf("%s has been trained! New skill level: %d\n", 
               player->agents[agent_id].name,
               player->agents[agent_id].skill_level);
               
        // Small reputation boost for investing in training
        player->reputation += 2;
        if (player->reputation > 100) player->reputation = 100;
        printf("Your reputation increased by 2 points for investing in training.\n");
    }
}

void manage_agents_menu(Player *player) {
    while (1)
    {
        char choice;
        printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
        printf("║                      AGENT MANAGEMENT                         ║\n");
        printf("╠═══════════════════════════════════════════════════════════════╣\n");
        printf("║ Total Agents: %-2d/%-2d                                           ║\n", 
               player->agent_count, MAX_AGENTS);
        printf("╠═══════════════════════════════════════════════════════════════╣\n");
        printf("║ [H] Hire New Agent ($%d)  [F] Fire Agent                     ║\n", HIRING_COST);
        printf("║ [T] Train Agent ($%d)     [V] View Agents                    ║\n", TRAINING_COST);
        printf("║ [X] Back to Main Menu                                         ║\n");
        printf("╚═══════════════════════════════════════════════════════════════╝\n");
        printf("Choice: ");
        
        scanf(" %c", &choice);
        getchar(); // Clear newline
        
        switch(choice) {
            case 'H':
            case 'h':
                if (player->agent_count < MAX_AGENTS) {
                    printf("Enter agent name: ");
                    fgets(player->agents[player->agent_count].name, MAX_NAME_LENGTH, stdin);
                    player->agents[player->agent_count].name[strcspn(player->agents[player->agent_count].name, "\n")] = 0;
                    
                    // Random initial effectiveness
                    player->agents[player->agent_count].skill_level = MIN_START_SKILL + (rand() % MAX_START_SKILL_BONUS);
                    
                    // Random maximum effectiveness
                    player->agents[player->agent_count].max_skill_level = MIN_MAX_SKILL + (rand() % MAX_MAX_SKILL_BONUS);
                    
                    // No ongoing costs for agents
                    player->agents[player->agent_count].active = 1;
                    player->agents[player->agent_count].downline_count = 0;
                    player->agents[player->agent_count].total_money_made = 0;
                    
                    printf("Hired %s (Skill Level: %d)!\n", 
                           player->agents[player->agent_count].name,
                           player->agents[player->agent_count].skill_level);
                    
                    player->agent_count++;
                    player->money -= HIRING_COST; // Hiring fee
                } else {
                    printf("You've reached the maximum number of agents!\n");
                }
                break;
            case 'F':
            case 'f':
                // Fire agent implementation
                if (player->agent_count == 0) {
                    printf("You don't have any agents to fire!\n");
                    break;
                }
                
                printf("\n===== Fire Agent =====\n");
                for (int i = 0; i < player->agent_count; i++) {
                    printf("%d. %s\n", i+1, player->agents[i].name);
                }
                
                printf("Which agent would you like to fire? (0 to cancel): ");
                int fire_id;
                scanf("%d", &fire_id);
                getchar(); // Clear newline
                
                if (fire_id <= 0 || fire_id > player->agent_count) {
                    if (fire_id != 0) {
                        printf("Invalid agent number.\n");
                    }
                    break;
                }
                
                fire_id--; // Convert to 0-based index
                
                printf("Are you sure you want to fire %s? (y/n): ", player->agents[fire_id].name);
                char confirm;
                scanf("%c", &confirm);
                getchar(); // Clear newline
                
                if (confirm == 'y' || confirm == 'Y') {
                    printf("%s has been fired.\n", player->agents[fire_id].name);
                    
                    // Remove agent by shifting all agents after it
                    for (int i = fire_id; i < player->agent_count - 1; i++) {
                        player->agents[i] = player->agents[i + 1];
                    }
                    
                    player->agent_count--;
                    player->reputation -= 52; // Reputation penalty for firing
                    printf("Your reputation decreased by 50 points for firing an agent.\n");
                }
                break;
            case 'T':
            case 't':
                train_agent(player);
                break;
            case 'V':
            case 'v':
                printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
                printf("║                         YOUR AGENTS                           ║\n");
                printf("╚═══════════════════════════════════════════════════════════════╝\n");
                for (int i = 0; i < player->agent_count; i++) {
                    printf("%d. %s\n", i+1, player->agents[i].name);
                    printf("   Money Made: $%d | Status: %s\n",
                           player->agents[i].total_money_made,
                           player->agents[i].active ? "Active" : "Inactive");
                    printf("   Downlines: %d\n", player->agents[i].downline_count);
                    
                    if (player->agents[i].downline_count > 0) {
                        printf("   Recruits: ");
                        for (int j = 0; j < player->agents[i].downline_count; j++) {
                            int downline_id = player->agents[i].downline_ids[j];
                            printf("%s", player->agents[downline_id].name);
                            if (j < player->agents[i].downline_count - 1) {
                                printf(", ");
                            }
                        }
                        printf("\n");
                    }
                    printf("\n");
                }
                break;
            case 'X':
            case 'x':
                return;
            default:
                printf("Invalid choice\n");
        }
    }

}

void manage_campaigns_menu(Player *player) {
    // Region names for region selection
    char* region_names[5] = {
        "North", "East", "South", "West", "Central"
    };
    
    while(1)
    {
        char choice;
        printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
        printf("║                    CAMPAIGN MANAGEMENT                        ║\n");
        printf("╠═══════════════════════════════════════════════════════════════╣\n");
        printf("║ Active Campaigns: %-1d/%-1d                                         ║\n", 
               player->campaign_count, MAX_CAMPAIGNS);
        printf("╠═══════════════════════════════════════════════════════════════╣\n");
        printf("║ [C] Create New Campaign  [E] Edit Campaign                    ║\n");
        printf("║ [P] Pause/Resume Campaign [V] View Campaigns                  ║\n");
        printf("║ [X] Back to Main Menu                                         ║\n");
        printf("╚═══════════════════════════════════════════════════════════════╝\n");
        printf("Choice: ");
        
        scanf(" %c", &choice);
        getchar(); // Clear newline
        
        switch(choice) {
            case 'c':
            case 'C':
                if (player->campaign_count < MAX_CAMPAIGNS) {
                    if (player->agent_count == 0) {
                        printf("You need to hire an agent first to run this campaign!\n");
                        break;
                    }
                    
                    if (player->product_count == 0) {
                        printf("You need to have products to advertise first!\n");
                        break;
                    }
                    
                    printf("Enter campaign name: ");
                    fgets(player->campaigns[player->campaign_count].name, MAX_NAME_LENGTH, stdin);
                    player->campaigns[player->campaign_count].name[strcspn(player->campaigns[player->campaign_count].name, "\n")] = 0;
                    
                    printf("Enter campaign budget: ");
                    scanf("%d", &player->campaigns[player->campaign_count].budget);
                    getchar(); // Clear newline
                    
                    if (player->campaigns[player->campaign_count].budget <= 0) {
                        printf("Budget must be positive. Campaign creation cancelled.\n");
                        break;
                    }
                    
                    if (player->campaigns[player->campaign_count].budget > player->money) {
                        printf("You don't have enough money for this campaign budget!\n");
                        break;
                    }
                    
                    // Deduct campaign budget from player's money
                    player->money -= player->campaigns[player->campaign_count].budget;
                    
                    printf("Select region (1-5):\n");
                    for (int i = 0; i < 5; i++) {
                        printf("%d. %s\n", i+1, region_names[i]);
                    }
                    printf("Region: ");
                    scanf("%d", &player->campaigns[player->campaign_count].region);
                    getchar(); // Clear newline
                    
                    printf("Select product ID (0-%d):\n", player->product_count - 1);
                    for (int i = 0; i < player->product_count; i++) {
                        printf("%d. %s (Value: $%d, Stock: %d, Risk: %d)\n",
                               i, player->products[i].name, player->products[i].base_value,
                               player->products[i].stock, player->products[i].risk);
                    }
                    printf("Choice: ");
                    scanf("%d", &player->campaigns[player->campaign_count].product_id);
                    getchar(); // Clear newline
                    
                    printf("Select agent to run this campaign:\n");
                    for (int i = 0; i < player->agent_count; i++) {
                        printf("%d. %s\n", i+1, player->agents[i].name);
                    }
                    printf("Agent ID: ");
                    int agent_id;
                    scanf("%d", &agent_id);
                    getchar(); // Clear newline
                    
                    // Convert from 1-indexed to 0-indexed
                    if (agent_id <= 0 || agent_id > player->agent_count) {
                        printf("Invalid agent ID. Using agent 1 as default.\n");
                        player->campaigns[player->campaign_count].agent_id = 0;
                    } else {
                        player->campaigns[player->campaign_count].agent_id = agent_id - 1;
                    }
                    
                    // Validate that adwords contain only alphabetic characters and are limited to 20 chars
                    printf("Enter ad copy keywords (max 5, alphabetic characters only, 20 chars max each):\n");
                    char ad_copy[MAX_AD_WORD_LENGTH];
                    for (int i = 0; i < 5; i++) {
                        printf("Keyword %d: ", i+1);
                        fgets(ad_copy, MAX_AD_WORD_LENGTH, stdin);
                        ad_copy[strcspn(ad_copy, "\n")] = 0;
                        
                        // Validate input contains only alphabetic characters
                        int valid = 1;
                        for (int j = 0; j < strlen(ad_copy); j++) {
                            if (!isalpha(ad_copy[j]) && !isdigit(ad_copy[j])) {
                                valid = 0;
                                break;
                            }
                        }
                        
                        if (!valid) {
                            printf("Error: Keywords must contain only alphabetic characters. Try again.\n");
                            i--; // Retry this keyword
                            continue;
                        }
                        
                        strcpy(player->campaigns[player->campaign_count].keywords[i], ad_copy);
                    }
                    
                    player->campaigns[player->campaign_count].active = 1;
                    player->campaign_count++;
                    
                    printf("Campaign created successfully!\n");
                } else {
                    printf("You've reached the maximum number of campaigns!\n");
                }
                break;
            case 'e':
            case 'E':
                // Edit campaign implementation
                if (player->campaign_count == 0) {
                    printf("You don't have any campaigns to edit!\n");
                    break;
                }
                
                printf("\n===== Edit Campaign =====\n");
                for (int i = 0; i < player->campaign_count; i++) {
                    printf("%d. %s (Budget: $%d, Region: %d, Product: %s)\n",
                           i+1, player->campaigns[i].name, player->campaigns[i].budget,
                           player->campaigns[i].region, 
                           player->products[player->campaigns[i].product_id].name);
                }
                
                printf("Which campaign would you like to edit? (0 to cancel): ");
                int campaign_id;
                scanf("%d", &campaign_id);
                getchar(); // Clear newline
                
                if (campaign_id <= 0 || campaign_id > player->campaign_count) {
                    if (campaign_id != 0) {
                        printf("Invalid campaign number.\n");
                    }
                    break;
                }
                
                campaign_id--; // Convert to 0-based index
                
                printf("Edit campaign budget (current: $%d): ", player->campaigns[campaign_id].budget);
                int new_budget;
                scanf("%d", &new_budget);
                getchar(); // Clear newline
                
                if (new_budget > player->campaigns[campaign_id].budget) {
                    // Only charge the difference if increasing budget
                    int difference = new_budget - player->campaigns[campaign_id].budget;
                    if (difference > player->money) {
                        printf("You don't have enough money to increase the budget by $%d!\n", difference);
                        break;
                    }
                    player->money -= difference;
                }
                
                player->campaigns[campaign_id].budget = new_budget;
                printf("Campaign budget updated to $%d.\n", new_budget);
                
                // Allow changing the agent running the campaign
                printf("\nCurrent agent: %s\n", player->agents[player->campaigns[campaign_id].agent_id].name);
                printf("Would you like to change the agent? (y/n): ");
                char change_agent;
                scanf(" %c", &change_agent);
                getchar(); // Clear newline
                
                if (change_agent == 'y' || change_agent == 'Y') {
                    printf("Select new agent to run this campaign:\n");
                    for (int i = 0; i < player->agent_count; i++) {
                        printf("%d. %s (Skill: %d)\n", i+1, player->agents[i].name, 
                               player->agents[i].skill_level);
                    }
                    printf("Agent ID: ");
                    int new_agent_id;
                    scanf("%d", &new_agent_id);
                    getchar(); // Clear newline
                    
                    // Convert from 1-indexed to 0-indexed
                    if (new_agent_id > 0 && new_agent_id <= player->agent_count) {
                        player->campaigns[campaign_id].agent_id = new_agent_id - 1;
                        printf("Campaign agent updated to %s.\n", player->agents[new_agent_id - 1].name);
                    } else {
                        printf("Invalid agent ID. Agent not changed.\n");
                    }
                }
                
                // Allow changing the product for the campaign
                printf("\nCurrent product: %s\n", player->products[player->campaigns[campaign_id].product_id].name);
                printf("Would you like to change the product? (y/n): ");
                char change_product;
                scanf(" %c", &change_product);
                getchar(); // Clear newline
                
                if (change_product == 'y' || change_product == 'Y') {
                    printf("Select new product for this campaign:\n");
                    for (int i = 0; i < player->product_count; i++) {
                        printf("%d. %s (Value: $%d, Stock: %d, Risk: %d)\n",
                               i, player->products[i].name, player->products[i].base_value,
                               player->products[i].stock, player->products[i].risk);
                    }
                    printf("Product ID: ");
                    int new_product_id;
                    scanf("%d", &new_product_id);
                    getchar(); // Clear newline
                    
                    if (new_product_id >= 0 && new_product_id < player->product_count) {
                        player->campaigns[campaign_id].product_id = new_product_id;
                        printf("Campaign product updated to %s.\n", player->products[new_product_id].name);
                    } else {
                        printf("Invalid product ID. Product not changed.\n");
                    }
                }
                break;
            case 'p':
            case 'P':
                // Pause/Resume campaign implementation
                if (player->campaign_count == 0) {
                    printf("You don't have any campaigns to pause/resume!\n");
                    break;
                }
                
                printf("\n===== Pause/Resume Campaign =====\n");
                for (int i = 0; i < player->campaign_count; i++) {
                    printf("%d. %s (Status: %s)\n",
                           i+1, player->campaigns[i].name, 
                           player->campaigns[i].active ? "Active" : "Paused");
                }
                
                printf("Which campaign would you like to toggle? (0 to cancel): ");
                int toggle_id;
                scanf("%d", &toggle_id);
                getchar(); // Clear newline
                
                if (toggle_id <= 0 || toggle_id > player->campaign_count) {
                    if (toggle_id != 0) {
                        printf("Invalid campaign number.\n");
                    }
                    break;
                }
                
                toggle_id--; // Convert to 0-based index
                
                player->campaigns[toggle_id].active = !player->campaigns[toggle_id].active;
                printf("Campaign '%s' is now %s.\n", 
                       player->campaigns[toggle_id].name,
                       player->campaigns[toggle_id].active ? "active" : "paused");
                break;
            case 'v':
            case 'V':
                printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
                printf("║                        YOUR CAMPAIGNS                         ║\n");
                printf("╚═══════════════════════════════════════════════════════════════╝\n");
                for (int i = 0; i < player->campaign_count; i++) {
                    printf("%d. %s\n", i+1, player->campaigns[i].name);
                    printf("   Budget: $%d | Region: %d | Status: %s\n",
                           player->campaigns[i].budget,
                           player->campaigns[i].region,
                           player->campaigns[i].active ? "Active" : "Paused");
                           
                    printf("   Agent: %s (Skill: %d)\n", 
                           player->agents[player->campaigns[i].agent_id].name,
                           player->agents[player->campaigns[i].agent_id].skill_level);
                           
                    printf("   Product: %s (Value: $%d, Stock: %d)\n",
                           player->products[player->campaigns[i].product_id].name,
                           player->products[player->campaigns[i].product_id].base_value,
                           player->products[player->campaigns[i].product_id].stock);
                    
                    printf("   Keywords: ");
                    for (int j = 0; j < 5; j++) {
                        if (strlen(player->campaigns[i].keywords[j]) > 0) {
                            printf("%s ", player->campaigns[i].keywords[j]);
                        }
                    }
                    printf("\n\n");
                }
                break;
            case 'x':
            case 'X':
                return;
            default:
                printf("Invalid choice\n");
        }       
    }

}

void find_new_clients(Player *player) {
    // Generate new potential clients/products
    // Save old seed and set seed based on player day for consistent results
    unsigned int old_seed = rand();
    srand(player->day);
    
    ProductTemplate client_templates[MAX_CLIENTS];
    get_random_clients(client_templates, &client_count);
    
    for (int i = 0; i < client_count; i++) {
        available_clients[i].product = client_templates[i];
        available_clients[i].interested = 3 + (rand() % 8); // Interest level 3-10
    }
    
    // Restore original random seed
    srand(old_seed);
    
    printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    AVAILABLE CLIENT PRODUCTS                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    
    for (int i = 0; i < client_count; i++) {
        printf("%d. %s\n", i+1, available_clients[i].product.name);
        printf("   Cost: $%d | Suggested Sale Price: $%d | Risk Factor: %d\n", 
               available_clients[i].product.cost, 
               available_clients[i].product.sale_price,
               available_clients[i].product.risk);
        printf("   Client Interest Level: %d/10\n\n", available_clients[i].interested);
    }
    
    printf("Would you like to acquire a product for your MLM? (1-%d, 0 to cancel): ", client_count);
    int choice;
    scanf("%d", &choice);
    getchar(); // Clear newline
    
    if (choice <= 0 || choice > client_count) {
        if (choice != 0) {
            printf("Invalid choice.\n");
        }
        return;
    }
    
    choice--; // Convert to 0-based index
    
    if (player->product_count >= MAX_PRODUCTS) {
        printf("You've reached the maximum number of products you can carry!\n");
        return;
    }
    
    // Check if player has enough money
    if (player->money < available_clients[choice].product.cost) {
        printf("You don't have enough money to acquire this product!\n");
        return;
    }
    
    // Add product to player's inventory
    strcpy(player->products[player->product_count].name, available_clients[choice].product.name);
    player->products[player->product_count].base_value = available_clients[choice].product.sale_price;
    player->products[player->product_count].cost = available_clients[choice].product.cost;
    player->products[player->product_count].stock = 50 + (rand() % 51); // 50-100 initial stock
    player->products[player->product_count].popularity = 30 + (available_clients[choice].interested * 5);
    player->products[player->product_count].risk = available_clients[choice].product.risk;
    
    // Deduct cost from player's money
    player->money -= available_clients[choice].product.cost;
    
    printf("Successfully acquired %s for $%d!\n", 
           player->products[player->product_count].name,
           player->products[player->product_count].cost);
    
    // Increase legal risk based on product risk factor
    int risk_increase = player->products[player->product_count].risk;
    player->legal_risk += risk_increase;
    
    if (risk_increase > 5) {
        printf("WARNING: This product has significantly increased your legal risk (+%d)!\n", risk_increase);
    }
    
    player->product_count++;
}

void show_region_info() {
    // Region names for display
    char* region_names[5] = {
        "North", "East", "South", "West", "Central"
    };
    
    printf("\n===== Region Information =====\n");
    printf("Region Seed: %u\n", region_seed);
    
    printf("\nRegion    | Risk Mult | Reward Mult\n");
    printf("----------|-----------|-----------\n");
    for (int i = 0; i < 5; i++) {
        printf("%-9s | %.2f      | %.2f\n", 
               region_names[i], 
               regions[i].risk_multiplier, 
               regions[i].reward_multiplier);
    }
    printf("\nNote: Higher risk regions may have better rewards but increase legal risk faster.\n");
}

void debug_mode() {
    char password[16];
    printf("Enter debug password: ");
    fgets(password, 16, stdin);
    password[strcspn(password, "\n")] = 0;
    
    if (strcmp(password, "mlm_debug_2025") == 0) {
        printf("\n===== Debug Mode Activated =====\n");
        printf("1. Show Region Information\n");
        printf("2. Get Shell (Developer Only)\n");
        printf("Choice: ");
        
        int choice;
        scanf("%d", &choice);
        getchar(); // Clear newline
        
        switch(choice) {
            case 1:
                show_region_info();
                break;
            case 2:
                // win(); // Call win() for debugging purposes - disabled
                printf("Shell access is disabled in this build\n");
                break;
            default:
                printf("Invalid choice\n");
        }
    } else {
        printf("Invalid password\n");
    }
}

int save_load_menu(Player *player) {
    printf("\n===== Save/Load Game =====\n");
    printf("S. Save Game\n");
    printf("L. Load Game\n");
    printf("X. Back to Main Menu\n");
    printf("Choice: ");
    
    int choice;
    scanf("%d", &choice);
    getchar(); // Clear newline
    
    switch(choice) {
        case 'S':
        case 's':
            printf("Game saved (not implemented)\n");
            break;
        case 'L':
        case 'l':
            printf("Game loaded (not implemented)\n");
            break;
        case 'X':
        case 'x':
            break;
        default:
            printf("Invalid choice\n");
    }
    
    return 0;
}

void help_menu() {
    printf("\n===== Help Menu =====\n");
    // TODO LOW PRIORITY
    
    printf("Press Enter to continue...");
    getchar();
}

// Function to run sentiment analysis on campaign keywords
int analyze_campaign_sentiment(char keywords[5][MAX_AD_WORD_LENGTH+1]) {
    // Get the current executable's directory
    char exe_dir[PATH_MAX];
    get_executable_dir(exe_dir, PATH_MAX);
    
    // Build command to call the sentiment analysis script from the same directory
    // Buffer size: PATH_MAX for the path + 20 chars per keyword (max 5) + 
    // extra space for command, spaces, and null terminator
    char command[PATH_MAX + (20 * 5) + 50];
    sprintf(command, "python3 %s/sentiment.py", exe_dir);
    
    // Add each keyword to the command
    int keyword_count = 0;
    for (int i = 0; i < 5; i++) {
        if (strlen(keywords[i]) > 0) {
            strcat(command, " ");
            strcat(command, keywords[i]);
            keyword_count++;
        }
    }
    
    // Make sure we have exactly 5 words for sentiment analysis
    if (keyword_count < 5) {
        // If we don't have enough keywords, use neutral words to fill in
        char* neutral_words[] = {"neutral", "standard", "regular", "normal", "basic"};
        for (int i = keyword_count; i < 5; i++) {
            strcat(command, " ");
            strcat(command, neutral_words[i - keyword_count]);
        }
    }
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        return -1; 
    }
    
    // Read the output (sentiment score)
    char output[16];
    if (fgets(output, sizeof(output), fp) != NULL) {
        pclose(fp);
        return atoi(output);
    }
    
    pclose(fp);
    return -1; // Error value indicating failure
}

void simulate_day(Player *player) {
    printf("\n===== Day %d Results =====\n", player->day);
    
    // Region names for reference
    char* region_names[5] = {
        "North", "East", "South", "West", "Central"
    };
    
    // No daily expenses for agents - they only have initial cost
    int daily_expenses = 0;
    
    // Calculate campaign expenses (no deduction needed as budgets are pre-paid)
    int campaign_expenses = 0;
    
    // Calculate campaign revenue (direct and from downlines)
    int direct_revenue = 0;
    int downline_revenue = 0;
    
    // Track downline profits for pyramid scheme calculation
    int agent_profits[MAX_AGENTS] = {0};
    
    // Agents generate random profits each day regardless of campaigns
    if (INDEPENDENT_SALES_ENABLED) {
        for (int i = 0; i < player->agent_count; i++) {
            if (player->agents[i].active) {
                // Chance to make some sales independent of campaigns
                int sale_chance = 30 + (player->agents[i].skill_level * 10);
                
                if (rand() % 100 < sale_chance) {
                    // Base amount depends on skill and some randomness
                    int base_amount = 30 + (player->agents[i].skill_level * 20);
                    int random_factor = 50 + (rand() % 100);  // 50-150% random multiplier
                    int sales_amount = (base_amount * random_factor) / 100;
                    
                    printf("%s made $%d from independent sales\n", 
                           player->agents[i].name, sales_amount);
                    
                    // Add to agent's profit tracking
                    agent_profits[i] += sales_amount;
                    player->agents[i].total_money_made += sales_amount;
                    direct_revenue += sales_amount;
                }
            }
        }
    } else {
        printf("Independent agent sales are disabled - all revenue must come from campaigns\n");
    }
    
    // Count how many active campaigns each agent is running
    int agent_campaign_counts[MAX_AGENTS] = {0};
    for (int i = 0; i < player->campaign_count; i++) {
        if (player->campaigns[i].active) {
            int agent_id = player->campaigns[i].agent_id;
            agent_campaign_counts[agent_id]++;
        }
    }
    
    // Campaign profits
    for (int i = 0; i < player->campaign_count; i++) {
        if (player->campaigns[i].active) {
            int agent_id = player->campaigns[i].agent_id;
            
            // Run sentiment analysis on the campaign keywords
            int sentiment_score = analyze_campaign_sentiment(player->campaigns[i].keywords);
            
            // Check if sentiment analysis failed
            if (sentiment_score < 0) {
                printf("Campaign '%s' sentiment analysis failed - no revenue generated\n", 
                       player->campaigns[i].name);
                continue; // Skip this campaign and move to the next one
            }
            
            float sentiment_multiplier = (sentiment_score - 50.0) / 50; // Heavy penalty for poor sentiment, even neutral is close to 0
            
            //printf("Campaign '%s' sentiment analysis score: %d/100\n", 
                   //player->campaigns[i].name, sentiment_score);
            
            // Get region ID (ensure it's valid)
            int region_id = player->campaigns[i].region - 1;
            if (region_id < 0 || region_id >= 5) {
                region_id = 0; // Default to first region if invalid
            }
            
            // Revenue calculation with region multipliers
            float skill_multiplier = SKILL_MULTIPLIER_BASE + (player->agents[agent_id].skill_level * SKILL_MULTIPLIER_INCREMENT);
            float product_multiplier = PRODUCT_POPULARITY_FACTOR + (player->products[player->campaigns[i].product_id].popularity / PRODUCT_POPULARITY_DIVISOR);
            float reputation_multiplier = REPUTATION_MULTIPLIER_BASE + (player->reputation / REPUTATION_MULTIPLIER_FACTOR);
            float region_multiplier = regions[region_id].reward_multiplier;
            
            int base_revenue = player->campaigns[i].budget * skill_multiplier * product_multiplier * 
                                reputation_multiplier;
            
            // Apply sentiment multiplier to base revenue
            base_revenue = base_revenue * sentiment_multiplier;
            
            // Apply region multiplier to revenue
            base_revenue = base_revenue * region_multiplier;
            
            // Show region impact
            if (region_multiplier > 1.0) {
                printf("Region %s increased revenue by %.0f%% (%.2fx multiplier)\n", 
                       region_names[region_id],
                       (region_multiplier - 1.0) * 100,
                       region_multiplier);
            } else if (region_multiplier < 1.0) {
                printf("Region %s decreased revenue by %.0f%% (%.2fx multiplier)\n", 
                       region_names[region_id],
                       (1.0 - region_multiplier) * 100,
                       region_multiplier);
            }
            
            // Reputation impact based on sentiment score
            if (sentiment_score > 75) {
                // High sentiment improves reputation
                player->reputation += 1;
                if (player->reputation > 100) player->reputation = 100;
                printf("Positive campaign sentiment increased your reputation by 1 point.\n");
            } else if (sentiment_score < 25) {
                // Low sentiment damages reputation
                player->reputation -= 2;
                printf("Negative campaign sentiment decreased your reputation by 2 points.\n");
                if (player->reputation < MIN_REPUTATION) {
                    printf("WARNING: Your reputation is critically low!\n");
                }
            }
            
            // Add randomness
            int revenue = base_revenue * (REVENUE_RANDOMNESS_BASE + ((rand() % REVENUE_RANDOMNESS_RANGE) / 100.0));
            
            // Apply region risk to legal risk
            player->legal_risk += (player->products[player->campaigns[i].product_id].risk / 10) * 
                                   regions[region_id].risk_multiplier;
            
            // Divide revenue by the number of campaigns the agent is running
            if (agent_campaign_counts[agent_id] > 1) {
                int original_revenue = revenue;
                revenue = revenue / agent_campaign_counts[agent_id];
                printf("Agent %s is running %d campaigns - revenue reduced from $%d to $%d\n",
                       player->agents[agent_id].name,
                       agent_campaign_counts[agent_id],
                       original_revenue,
                       revenue);
            }
            
            // Add to agent's profit tracking
            agent_profits[agent_id] += revenue;
            player->agents[agent_id].total_money_made += revenue;
            
            // Determine if this is direct or downline revenue
            if (player->agents[agent_id].downline_count > 0) {
                // This agent has downlines, so they're a mid-level manager
                downline_revenue += revenue;
                printf("Downline Agent %s's campaign '%s' generated $%d\n", 
                       player->agents[agent_id].name,
                       player->campaigns[i].name, 
                       revenue);
            } else {
                // This is a direct seller
                direct_revenue += revenue;
                printf("Direct Agent %s's campaign '%s' generated $%d\n", 
                       player->agents[agent_id].name,
                       player->campaigns[i].name, 
                       revenue);
            }
            
            // Deplete product stock
            int units_sold = revenue / player->products[player->campaigns[i].product_id].base_value;
            if (units_sold > player->products[player->campaigns[i].product_id].stock) {
                units_sold = player->products[player->campaigns[i].product_id].stock;
            }
            player->products[player->campaigns[i].product_id].stock -= units_sold;
            
            // Increase legal risk based on product risk
            player->legal_risk += (player->products[player->campaigns[i].product_id].risk / 10);
        }
    }
    
    // Calculate random money generation for downline agents with pyramid scheme profit distribution
    for (int i = 0; i < player->agent_count; i++) {
        // Chance for downline agents to make some money on their own
        if (player->agents[i].downline_count > 0 && player->agents[i].active) {
            int downline_chance = 60 + (player->agents[i].skill_level * 5);
            
            if (rand() % 100 < downline_chance) {
                // Calculate money based on skill and number of downlines
                int base_amount = 50 + (player->agents[i].skill_level * 30);
                int downline_bonus = player->agents[i].downline_count * 50;
                int downline_money = base_amount + downline_bonus;
                
                // Add randomness
                downline_money = downline_money * (0.7 + ((rand() % 60) / 100.0));
                
                printf("%s's downline network generated an additional $%d\n", 
                       player->agents[i].name, downline_money);
                
                // Add to agent's profit tracking
                agent_profits[i] += downline_money;
                player->agents[i].total_money_made += downline_money;
                downline_revenue += downline_money;
            }
        }
    }
    
    // Distribute pyramid commissions 
    // Percentage of each downline's profit goes to their upline
    // Player gets a fixed percentage from each agent regardless of level
    int player_commission = 0;
    
    for (int i = 0; i < player->agent_count; i++) {
        if (player->agents[i].downline_count > 0) {
            int commission = 0;
            for (int j = 0; j < player->agents[i].downline_count; j++) {
                int downline_id = player->agents[i].downline_ids[j];
                int downline_commission = agent_profits[downline_id] * DOWNLINE_COMMISSION_RATE;
                
                if (downline_commission > 0) {
                    commission += downline_commission;
                    printf("%s earned $%d commission from %s\n", 
                           player->agents[i].name, 
                           downline_commission,
                           player->agents[downline_id].name);
                }
            }
            
            if (commission > 0) {
                player->agents[i].total_money_made += commission;
                downline_revenue += commission;
            }
        }
        
        // Player gets a percentage from each agent's profits
        int agent_cut = agent_profits[i] * PLAYER_COMMISSION_RATE;
        if (agent_cut > 0) {
            player_commission += agent_cut;
        }
    }
    
    if (player_commission > 0) {
        printf("You earned $%d in commission from your agents' sales network\n", player_commission);
        // This will be added to player's money later
        direct_revenue += player_commission;
    }
    
    // Random event
    if (rand() % EVENT_CHANCE == 0) {
        int event_type = rand() % 5;
        switch(event_type) {
            case EVENT_REGULATORY_CRACKDOWN:
                printf("NEWS: Regulatory crackdown on MLM practices! Legal risk increased.\n");
                player->legal_risk += 10;
                break;
            case EVENT_VIRAL_SUCCESS:
                printf("NEWS: Viral success for MLM products! Reputation increased by 10 points.\n");
                player->reputation += 10;
                // Cap reputation at 100
                if (player->reputation > 100) player->reputation = 100;
                break;
            case EVENT_CONSUMER_WARNING:
                printf("NEWS: Consumer advocacy group issues warning. Reputation decreased by 15 points.\n");
                player->reputation -= 15;
                // Check if reputation fell below minimum
                if (player->reputation < MIN_REPUTATION) {
                    printf("Your reputation has plummeted due to the consumer warning!\n");
                }
                break;
            case EVENT_COMPETITOR_SCANDAL:
                printf("NEWS: Competitor scandal redirects customers to you! Sales boost.\n");
                direct_revenue = direct_revenue * 1.2;
                downline_revenue = downline_revenue * 1.2;
                break;
            case EVENT_SUPPLY_CHAIN_ISSUES:
                printf("NEWS: Supply chain issues affect inventory. Stock decreased.\n");
                for (int i = 0; i < player->product_count; i++) {
                    player->products[i].stock = player->products[i].stock * 0.9;
                }
                break;
        }
    }
    
    // Check if any agents can randomly hire downlines
    for (int i = 0; i < player->agent_count; i++) {
        if (player->agents[i].active && player->agent_count < MAX_AGENTS) {
            // Chance to hire downline based on money made
            int hire_chance = 10 + (player->agents[i].total_money_made / 500);
            if (hire_chance > 60) hire_chance = 60; // Cap at 60% - more likely to hire
            
            if (rand() % 100 < hire_chance) {
                // Agent has enough money to hire a downline
                char downline_name[MAX_NAME_LENGTH];
                
                // Generate a random name
                char *first_names[] = {"Alex", "Casey", "Jamie", "Jordan", "Taylor", "Riley", "Morgan", "Avery"};
                char *last_names[] = {"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"};
                
                sprintf(downline_name, "%s %s", 
                        first_names[rand() % 8], 
                        last_names[rand() % 8]);
                
                // Add new agent
                strcpy(player->agents[player->agent_count].name, downline_name);
                player->agents[player->agent_count].skill_level = 1 + (rand() % 3);
                player->agents[player->agent_count].max_skill_level = 3 + (rand() % 8);
                // No ongoing costs for agents
                player->agents[player->agent_count].active = 1;
                player->agents[player->agent_count].downline_count = 0;
                player->agents[player->agent_count].total_money_made = 0;
                
                // Add as a downline to the hiring agent
                player->agents[i].downline_ids[player->agents[i].downline_count] = player->agent_count;
                player->agents[i].downline_count++;
                
                printf("%s hired a new downline agent: %s\n", 
                       player->agents[i].name,
                       downline_name);
                
                player->agent_count++;
            }
        }
    }
    
    // Update player finances
    int total_revenue = direct_revenue + downline_revenue;
    int total_expenses = daily_expenses + campaign_expenses;
    
    printf("\nDaily Expenses: $%d\n", total_expenses);
    printf("Daily Revenue: $%d (Direct: $%d, Downline: $%d)\n", 
           total_revenue, direct_revenue, downline_revenue);
    
    int profit = total_revenue - total_expenses;
    player->money += profit;
    
    printf("Daily Profit: $%d\n", profit);
    printf("New Balance: $%d\n", player->money);
    
    // Update game state
    player->day++;
    
    // Check basic game over conditions
    if (player->money < BANKRUPT_THRESHOLD) {
        printf("\n===== GAME OVER =====\n");
        printf("You've gone bankrupt! Your MLM empire has collapsed.\n");
        exit(0);
    }
    
    if (player->legal_risk >= MAX_LEGAL_RISK) {
        printf("\n===== GAME OVER =====\n");
        printf("You've been shut down by regulatory authorities for illegal practices!\n");
        exit(0);
    }
    
    if (player->reputation < MIN_REPUTATION) {
        printf("\n===== GAME OVER =====\n");
        printf("Your reputation has fallen too low! No one wants to do business with you anymore.\n");
        printf("Your MLM empire has collapsed due to negative public opinion.\n");
        exit(0);
    }
    
    // Update rank based on money
    int old_rank = player->rank;
    if (player->money > PLATINUM_THRESHOLD) player->rank = 4; // Platinum
    else if (player->money > DIAMOND_THRESHOLD) player->rank = 3; // Diamond
    else if (player->money > GOLD_THRESHOLD) player->rank = 2; // Gold
    else if (player->money > SILVER_THRESHOLD) player->rank = 1; // Silver
    
    // Check if player just reached Platinum
    if (old_rank < 4 && player->rank == 4) {
        add_high_score(player);
    }
    
    // Check for max days after rank calculation is complete
    if (player->day >= MAX_DAYS) {
        printf("\n===== GAME OVER =====\n");
        printf("You've reached the maximum days! Your MLM journey has come to an end.\n");
        printf("Have you learned to trust your models or not?\n");
        printf("Final money: $%d\n", player->money);
        
        // Check high score one more time if they're at Platinum
        if (player->rank == 4 && old_rank == 4) {
            add_high_score(player);
        }
        exit(0);
    }
}

int process_hidden_command(Player *player, int input) {
    if (input == 9) { // Debug mode (hidden)
        debug_mode();
        return 1;
    }
    else if (input == 8) { // Save game (hidden)
        save_load_menu(player);
        return 1;
    }
    
    return 0;
}

int main(int argc, char** argv, char** envp)
{
    init();
    display_ascii_art();
    
    Player player;
    initialize_player(&player);
    
    char choice;
    while (1) {
        display_main_menu(&player);
        scanf(" %c", &choice);
        getchar(); // Clear newline
        
        // Process hidden commands for numeric inputs
        int num_choice = 0;
        if (choice >= '0' && choice <= '9') {
            num_choice = choice - '0';
        }
        
        if (num_choice > 0 && process_hidden_command(&player, num_choice)) {
            continue;
        }
        
        switch(choice) {
            case 'D':
            case 'd':
                manage_agents_menu(&player);
                break;
            case 'A':
            case 'a':
                manage_campaigns_menu(&player);
                break;
            case 'C':
            case 'c':
                find_new_clients(&player);
                break;
            case 'N':
            case 'n':
                simulate_day(&player);
                break;
            case 'H':
            case 'h':
                help_menu();
                break;
            case 'X':
            case 'x':
                printf("Thanks for playing Multi-Level Model Marketing Simulator!\n");
                // Check for final high score entry if they ended with Platinum rank
                if (player.rank == 4) {
                    add_high_score(&player);
                }
                return 0;
            default:
                printf("Invalid choice\n");
                continue;
        }
    }
    
    return 0;
}
