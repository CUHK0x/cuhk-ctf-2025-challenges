#include <exception>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>

using namespace std;

const char *MSG = "FS: Anyone play Palworld?";

constexpr char SEP = ';';

void win() {
    cout << "Not so easy after all, is it?" << endl;
    system("/bin/sh");
}

string prompt_str(string field_name) {
    cout << "Enter " << field_name << ": ";
    string s;
    getline(cin, s);
    return s;
}

int prompt_int(string field_name, int low, int high) {
    cout << "Enter " << field_name << " " << "(" << low << " ~ " << high << "): ";
    int val;
    cin >> val;
    // Always consume a line
    cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    if (cin.fail() || val < low || val > high) {
        cout << "Enter a vaild " << field_name << "!\n";
        cin.clear();
        return prompt_int(field_name, low, high);
    }
    return val;
}

// Vibe coded color function
// Not good coding practice, but the order should match the type
enum class Color {
    Red,
    Green,
    Brown,
    Blue,
    Yellow,
    Purple,
    Pink,
};

std::string colorText(const std::string& text, Color color) {
    // ANSI escape codes for colors
    const std::string reset = "\033[0m";
    std::string colorCode;

    switch (color) {
        case Color::Red:
            colorCode = "\033[31m";
            break;
        case Color::Yellow:
            colorCode = "\033[33m";
            break;
        case Color::Green:
            colorCode = "\033[32m";
            break;
        case Color::Brown:
            colorCode = "\033[38;5;94m"; // ANSI doesn't have a direct brown, using a close shade
            break;
        case Color::Blue:
            colorCode = "\033[34m";
            break;
        case Color::Purple:
            colorCode = "\033[35m";
            break;
        case Color::Pink:
            colorCode = "\033[38;5;206m"; // ANSI code for pink
            break;
    }

    return colorCode + text + reset;
}
// Vibe coded colour function end.

struct LivingThing {
    enum Gender {
        Male,
        Female,
        Unknown
    };
    unsigned int id;
    string name;
    unsigned int age;
    Gender gender;
    unsigned int hp = 100;
    virtual string str() const {
        stringstream ss;
        ss << id << '\t' << name << "\t(Gender: " << gender_str(gender) << ", Age: " << age << ", HP: " << hp << ")";
        return ss.str();
    }
    static string gender_str(Gender g) {
        switch (g) {
            case Male:
            return string("Male");
            case Female:
            return string("Female");
            case Unknown:
            return string("Unknown");
        }
        throw exception();
    }
    virtual stringstream sdump() const {
        stringstream ss;
        ss << id << SEP << name << SEP << age << SEP << gender << SEP << hp << SEP;
        return ss;
    }
    virtual void get_input() {
        name = prompt_str("Name");
        age = stoi(prompt_str("Age"));
        char gen_c = 0;
        while (gen_c == 0) {
            cout << "Enter Gender (M/F/?): ";
            cin >> gen_c;
            cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            gen_c = toupper(gen_c);
            switch (gen_c) {
                case 'M':
                gender = Gender::Male;
                break;
                case 'F':
                gender = Gender::Female;
                break;
                case '?':
                gender = Gender::Unknown;
                break;
                default:
                cout << "Invalid input!\n";
                cin.clear();
                cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                gen_c = 0;
                break;
            }
        }
    }
};

struct Human: LivingThing {
    string occupation;
    virtual string str() const override {
        stringstream ss;
        ss << id << " " << name << " (Gender: " << gender_str(gender) << ", Age: " << age << ", " << "Occupation: " << occupation << ")";
        return ss.str();
    }
    static unique_ptr<Human> sload(istream &is) {
        auto p_human = make_unique<Human>();
        string s;
        getline(is, s, SEP);
        p_human->id = stoi(s);
        getline(is, p_human->name, SEP);
        getline(is, s, SEP);
        p_human->age = stoi(s);
        getline(is, s, SEP);
        p_human->gender = static_cast<enum LivingThing::Gender>(stoi(s));
        getline(is, s, SEP);
        p_human->hp = stoi(s);
        getline(is, p_human->occupation, SEP);
        return p_human;
    }
    virtual stringstream sdump() const {
        return LivingThing::sdump() << occupation << SEP;
    }
    virtual void get_input() override {
        LivingThing::get_input();
        occupation = prompt_str("Occupation");
    }
};

struct Pal: LivingThing {
    enum Type {
        Fire,
        Grass,
        Earth,
        Water,
        Electric,
        Dark,
        Neutral,
    };
    Type type;
    static const unordered_map<Pal::Type, Color> colorMap;
    static const unordered_map<Pal::Type, string> typeName;
    virtual string str() const override {
        stringstream ss;
        ss << id << " " << colorText(name, Pal::colorMap.at(type))
           << " (Gender: " << gender_str(gender) << ", Age: " << age
           << ", Type: " << colorText(typeName.at(type), colorMap.at(type)) << ")";
        return ss.str();
    }
    static unique_ptr<Pal> sload(istream &is) {
        auto p_pal = make_unique<Pal>();
        string s;
        getline(is, s, SEP);
        p_pal->id = stoi(s);
        getline(is, p_pal->name, SEP);
        getline(is, s, SEP);
        p_pal->age = stoi(s);
        getline(is, s, SEP);
        p_pal->gender = static_cast<enum LivingThing::Gender>(stoi(s));
        getline(is, s, SEP);
        p_pal->hp = stoi(s);
        getline(is, s, SEP);
        p_pal->type = static_cast<enum Pal::Type>(stoi(s));
        return p_pal;
    }
    virtual stringstream sdump() const {
        return LivingThing::sdump() << type << SEP;
    }
    virtual void get_input() {
        LivingThing::get_input();
        // Too lazy, users can just enter numbers
        cout <<
    "\
Types:\n\
1. Fire\n\
2. Grass\n\
3. Earth\n\
4. Water\n\
5. Electric\n\
6. Dark\n\
7. Neutral\n";
        this->type = static_cast<Type>(prompt_int("type", 1, 7) - 1);
    }
};

const unordered_map<Pal::Type, Color> Pal::colorMap ({
    {Type::Fire, Color::Red},
    {Type::Electric, Color::Yellow},
    {Type::Grass, Color::Green},
    {Type::Water, Color::Blue},
    {Type::Dark, Color::Purple},
    {Type::Earth, Color::Brown},
    {Type::Neutral, Color::Pink},
});

const unordered_map<Pal::Type, string> Pal::typeName ({
    {Type::Fire, "Fire"},
    {Type::Electric, "Electric"},
    {Type::Grass, "Grass"},
    {Type::Water, "Water"},
    {Type::Dark, "Dark"},
    {Type::Earth, "Earth"},
    {Type::Neutral, "Neutral"},
});

class SerialConverter {
    public:
    static vector<unique_ptr<LivingThing>> load(istream &is) {
        vector<unique_ptr<LivingThing>> v;
        v.reserve(20);
        while (!is.eof()) {
            // get the type string
            string type_str;
            getline(is, type_str, SEP);
            // Add support for more types here if needed
            if (type_str == typeid(Human).name()) {
                v.emplace(v.end(), Human::sload(is));
            }
            else if (type_str == typeid(Pal).name()) {
                v.emplace(v.end(), Pal::sload(is));
            }
        }
        return v;
    }
    static string dump(const vector<std::unique_ptr<LivingThing>> &v) {
        stringstream ss;
        for (auto &&lt: v) {
            ss << typeid(*lt).name() << SEP << lt->sdump().str();
        }
        return ss.str();
    }
};

unique_ptr<Human> new_human_from_input(unsigned int id) {
    auto p_human = make_unique<Human>();
    p_human->id = id;
    p_human->get_input();
    return p_human;
}

unique_ptr<Pal> new_pal_from_input(unsigned int id) {
    auto p_pal = make_unique<Pal>();
    p_pal->id = id;
    p_pal->get_input();
    return p_pal;
}

void load_from_save(const vector<string> &saves, vector<unique_ptr<LivingThing>> &things) {
    if (saves.size() < 1) {
        cout << "No saves!" << endl;
        return;
    }
    int idx = prompt_int("Save Number", 1, saves.size()) - 1;
    stringstream save_stream(saves[idx]);
    auto data = SerialConverter::load(save_stream);
    for (auto &&thing: data) {
        auto our_thing_it = find_if(things.begin(), things.end(), [&](const unique_ptr<LivingThing> &lt) {return lt->id == thing->id;});
        if (our_thing_it == things.end()) {
            things.emplace_back(thing.release());
        } else {
            auto &our_thing = *our_thing_it;
            if (typeid(*our_thing) != typeid(*thing)) throw exception();
            // ! Unsafe code here: copy the data of the old thing to the current thing
            // copy living things data
            our_thing->id = thing->id;
            strcpy(&our_thing->name[0], thing->name.c_str()); // actually kind of obvious since we haven't used C functions at all in other places
            our_thing->age = thing->age;
            our_thing->gender = thing->gender;
            our_thing->hp = thing->hp;
            if (typeid(*our_thing) == typeid(Human)) {
                auto &our_human = (Human&)*our_thing;
                auto &their_human = (Human&)*thing;
                strcpy(&our_human.occupation[0], their_human.occupation.c_str());
            } else if (typeid(*our_thing) == typeid(Pal)) {
                auto &our_pal = (Pal&)*our_thing;
                auto &their_pal = (Pal&)*thing;
                our_pal.type = their_pal.type;
            } else throw exception();
        }
    }
    cout << "Save " << idx + 1 << " loaded!\n";
}

int main(int argc, char const *argv[])
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    cout <<
"\
=====================================\n\
Labour Information Management Program\n\
=====================================\n";
    vector<unique_ptr<LivingThing>> things;
    vector<string> saves;
    unsigned int next_id = 1;
    bool quit = false;
    while (!quit) {
        cout <<
"\
Choose your operation:\n\
1. Create a new human\n\
2. Create a new pal\n\
3. Print the workforce\n\
4. Save current data\n\
5. Load current data\n\
6. Clear current data\n\
7. Quit\n";
        int mode = prompt_int("mode", 1, 8);
        switch (mode) {
            case 1:
            things.push_back(new_human_from_input(next_id++));
            break;
            case 2:
            things.push_back(new_pal_from_input(next_id++));
            break;
            case 3:
            if (things.empty()) {
                cout << "No labourer is created!\n";
                break;
            }
            for (auto &&thing: things) {
                cout << thing->str() << '\n';
            }
            cout << flush;
            break;
            case 4:
            saves.push_back(SerialConverter::dump(things));
            cout << "Current profile saved to Save " << saves.size() << endl;
            // cout << saves[saves.size()-1] << endl;
            break;
            case 5:
            load_from_save(saves, things);
            break;
            case 6:
            things.clear();
            cout << "Data cleared!" << endl;
            break;
            case 7:
            quit = true;
            case 8:
            printf("\
Debug:\n\
load_from_save: %p\n\
prompt_str: %p\n\
main: %p\n", load_from_save, prompt_str, main);
            break;
        }
    }
    return 0;
}
