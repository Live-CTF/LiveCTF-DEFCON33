#ifndef PRODUCTS_H
#define PRODUCTS_H

#include <stdlib.h>

#define PRODUCT_COUNT 90

typedef struct ProductTemplate {
    char name[64];
    int cost;
    int sale_price;
    int risk; // 1-10 scale of shadiness (1 = legitimate, 10 = extremely shady)
} ProductTemplate;

ProductTemplate product_templates[PRODUCT_COUNT] = {
    // Legitimate products (low risk: 1-3)
    {"Essential Wellness Pack", 25, 50, 1},
    {"Super Antioxidant Blend", 15, 45, 1},
    {"Premium Weight Management System", 40, 95, 2},
    {"Daily Vitamin Complex", 12, 35, 1},
    {"Advanced Skincare Collection", 65, 130, 2},
    {"Detox Tea Program", 18, 40, 3},
    {"Energizing Supplement Pack", 30, 65, 2},
    {"Hair Revitalization Formula", 45, 90, 3},
    {"Joint Support System", 22, 55, 1},
    {"Immune Defense Boosters", 20, 50, 2},
    
    // Moderate risk products (risk: 4-6)
    {"Digestive Health Miracle", 35, 75, 4},
    {"Sleep Enhancement Formula", 28, 60, 4},
    {"Brain Focus Maximizer", 50, 100, 5},
    {"Complete Meal Replacement System", 32, 70, 4},
    {"Anti-Aging Serum Elite", 85, 180, 5},
    {"Premium Protein Bars (Box)", 25, 60, 4},
    {"Hydration Multiplier Packets", 15, 35, 4},
    {"Stress Elimination Complex", 30, 65, 5},
    {"Children's Growth Formula", 18, 45, 6},
    {"Collagen Beauty Builder", 40, 85, 5},
    {"Metabolism Booster Plus", 35, 70, 6},
    {"Organic Superfood Blend", 45, 95, 4},
    {"Athletic Performance Enhancer", 50, 110, 6},
    {"Heart Health Omega Complex", 38, 80, 4},
    {"Vision Restoration Formula", 32, 70, 5},
    {"Bone Density Booster", 25, 55, 5},
    {"Fat Burning Accelerator", 35, 75, 6},
    {"Men's Vitality Formula", 48, 100, 6},
    {"Women's Hormone Balancer", 45, 95, 5},
    {"Cellular Rejuvenation System", 55, 120, 6},
    
    // High risk products (risk: 7-10)
    {"Miracle Cancer Prevention Drops", 90, 250, 10},
    {"Age Reversal Complex", 120, 300, 8},
    {"Diabetes Cure Formula", 85, 195, 10},
    {"IQ Enhancement Serum", 75, 180, 9},
    {"Baldness Elimination System", 95, 220, 8},
    {"Psychic Ability Activator", 110, 275, 9},
    {"Heart Disease Reversal Program", 150, 320, 10},
    {"Arthritis Pain Eraser", 65, 175, 9},
    {"Memory Restoration Complex", 80, 195, 8},
    {"Chronic Pain Elimination System", 95, 240, 9},
    {"DNA Repair Concentrate", 135, 315, 10},
    {"Youth Extension Formula", 145, 350, 9},
    {"Cellular Corruption Cleanser", 110, 275, 8},
    {"Rapid Weight Loss Miracle", 75, 190, 9},
    {"Addiction Cure Protocol", 125, 295, 10},
    {"Disease Prevention Matrix", 105, 255, 9},
    {"Stem Cell Activator Elite", 160, 380, 9},
    {"Immune System Supercharger", 85, 210, 8},
    {"Allergy Elimination Complex", 70, 175, 9},
    {"Biological Age Reducer", 130, 305, 8},
    
    // Extremely dubious products (risk: 9-10)
    {"Mind Control Resistance Drops", 90, 230, 9},
    {"Government Toxin Neutralizer", 85, 215, 10},
    {"Telepathic Enhancement Formula", 120, 290, 9},
    {"Radiation Shield Tablets", 105, 260, 10},
    {"Cellular Immortality Program", 170, 410, 10},
    {"Secret Intelligence Booster", 100, 245, 9},
    {"Wealth Attraction Supplement", 90, 220, 10},
    {"Lottery Winning Enhancement", 110, 285, 10},
    {"Extrasensory Perception Formula", 130, 310, 9},
    {"Mind Reading Activator Complex", 145, 355, 10},
    
    // Additional health & wellness products (mixed risk)
    {"Muscle Builder X-treme", 55, 130, 7},
    {"Perfect Vision Restorer", 60, 150, 8},
    {"Natural Hair Regrowth System", 70, 165, 7},
    {"Advanced Pain Relief Formula", 45, 110, 6},
    {"Energy Amplifier Shot", 30, 70, 5},
    {"Elite Sleep Optimizer", 40, 95, 4},
    {"Mental Clarity Booster", 35, 85, 3},
    {"Longevity Enhancement Protocol", 95, 225, 8},
    {"Ultimate Detox Program", 75, 175, 7},
    {"Biological Cleansing System", 85, 195, 7},
    
    // Business opportunity products (high markup, high risk)
    {"Business Success Blueprint", 20, 199, 8},
    {"Millionaire Mindset Program", 15, 249, 9},
    {"Financial Freedom Formula", 25, 299, 8},
    {"Wealth Building System", 30, 349, 9},
    {"Passive Income Generator Kit", 35, 399, 9},
    {"Success Attraction Protocol", 40, 449, 10},
    {"Elite Entrepreneur Package", 50, 499, 8},
    {"Leadership Mastery System", 45, 399, 7},
    {"Sales Conversion Maximizer", 35, 349, 7},
    {"Social Media Empire Builder", 40, 399, 8},
    
    // More questionable health products
    {"EMF Shield Generator Pendant", 15, 150, 9},
    {"Quantum Energy Mis-Alignment Discs", 20, 170, 10},
    {"Negative Mood Generator Bracelet", 25, 160, 9},
    {"Radical Regret Serum", 30, 140, 8},
    {"Instant Immortality Pill", 40, 200, 10},
    {"Aura Cleansing Spray", 25, 120, 9},
    {"Chakra Balancing Mercury", 35, 180, 10},
    {"Structured Chlorine Vortex Wand", 45, 220, 9},
    {"Oblivion Ointment", 20, 100, 8},
    {"Potassium Cyanide Energy Locket", 30, 190, 10}
};

// Select a random subset of products (3-6) as potential "clients"
void get_random_clients(ProductTemplate clients[], int *count) {
    *count = 3 + rand() % 4; // 3-6 clients
    
    // Create a copy of indices array and shuffle it
    int indices[PRODUCT_COUNT];
    for (int i = 0; i < PRODUCT_COUNT; i++) {
        indices[i] = i;
    }
    
    // Simple Fisher-Yates shuffle
    for (int i = PRODUCT_COUNT - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = indices[i];
        indices[i] = indices[j];
        indices[j] = temp;
    }
    
    // Copy the selected products to clients array
    for (int i = 0; i < *count; i++) {
        clients[i] = product_templates[indices[i]];
    }
}

#endif /* PRODUCTS_H */