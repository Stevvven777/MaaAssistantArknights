#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include "Task/Roguelike/BlackFlow/BlackFlowSafetyPlanner.h"
#include "Task/Roguelike/BlackFlow/BlackFlowSafetyValue.h"
#include "Task/Roguelike/BlackFlow/BlackFlowStateSpace.h"

namespac
{
using namespace asst::blackflow;

struct BoundedOracleResult
{
    std::unordered_map<SafetyStateId, int> required_action_points;
    std::size_t fixed_point_passes = 0;
};

// Independent finite-state AND-OR oracle.  A configuration (state, AP) is winning
// iff there is an executable action for which every possible outcome is already
// winning.  AP values above the bound are saturated to the bound; every generated
// property-test case has zero AP gain, so saturation is never needed there.
BoundedOracleResult solve_with_bounded_and_or_oracle(const SafetyProblem& problem, int maximum_action_points)
{
    if (maximum_action_points < 0) {
        throw std::invalid_argument("negative oracle AP bound");
    }

    std::vector<SafetyStateId> state_ids;
    state_ids.reserve(problem.states.size());
    std::unordered_map<SafetyStateId, std::size_t> state_indices;
    for (const SafetyState& state : problem.states) {
        if (!state_indices.emplace(state.id, state_ids.size()).second) {
            throw std::invalid_argument("duplicate oracle state id");
        }
        state_ids.emplace_back(state.id);
    }

    std::vector<std::vector<const SafetyAction*>> actions_by_source(problem.states.size());
    for (const SafetyAction& action : problem.actions) {
        const auto source = state_indices.find(action.source);
        if (source == state_indices.end()) {
            throw std::invalid_argument("oracle action has missing source");
        }
        actions_by_source[source->second].emplace_back(&action);
    }

    std::vector<std::vector<bool>> winning(
        problem.states.size(),
        std::vector<bool>(static_cast<std::size_t>(maximum_action_points + 1), false));
    for (std::size_t state_index = 0; state_index < problem.states.size(); ++state_index) {
        if (problem.states[state_index].safe_exit) {
            std::fill(winning[state_index].begin(), winning[state_index].end(), true);
        }
    }

    BoundedOracleResult result;
    const std::size_t maximum_passes = problem.states.size() * static_cast<std::size_t>(maximum_action_points + 1) + 1;
    for (; result.fixed_point_passes < maximum_passes; ++result.fixed_point_passes) {
        bool changed = false;
        for (int action_points = 0; action_points <= maximum_action_points; ++action_points) {
            for (std::size_t state_index = 0; state_index < problem.states.size(); ++state_index) {
                if (winning[state_index][action_points]) {
                    continue;
                }
                for (const SafetyAction* action : actions_by_source[state_index]) {
                    if (action_points < action->minimum_action_points_to_start ||
                        action_points < action->action_point_cost || action->outcomes.empty()) {
                        continue;
                    }
                    bool every_outcome_wins = true;
                    for (const SafetyOutcome& outcome : action->outcomes) {
                        const auto successor = state_indices.find(outcome.successor);
                        if (successor == state_indices.end()) {
                            throw std::invalid_argument("oracle action has missing successor");
                        }
                        const int successor_action_points = std::min(
                            maximum_action_points,
                            action_points - action->action_point_cost + outcome.action_point_gain);
                        if (successor_action_points < 0 || !winning[successor->second][successor_action_points]) {
                            every_outcome_wins = false;
                            break;
                        }
                    }
                    if (every_outcome_wins) {
                        winning[state_index][action_points] = true;
                        changed = true;
                        break;
                    }
                }
            }
        }
        if (!changed) {
            break;
        }
    }

    for (std::size_t state_index = 0; state_index < problem.states.size(); ++state_index) {
        int requirement = UnreachableActionPointRequirement;
        for (int action_points = 0; action_points <= maximum_action_points; ++action_points) {
            if (winning[state_index][action_points]) {
                requirement = action_points;
                break;
            }
        }
        result.required_action_points.emplace(state_ids[state_index], requirement);

        bool seen_winning = false;
        for (int action_points = 0; action_points <= maximum_action_points; ++action_points) {
            if (winning[state_index][action_points]) {
                seen_winning = true;
            }
            if (seen_winning && !winning[state_index][action_points]) {
                throw std::logic_error("oracle violated AP monotonicity");
            }
        }
    }
    return result;
}

SafetyAction deterministic_action(
    std::string id,
    SafetyStateId source,
    SafetyStateId successor,
    int cost = 1,
    int minimum_action_points_to_start = 1)
{
    return SafetyAction {
        .id = std::move(id),
        .source = source,
        .action_point_cost = cost,
        .minimum_action_points_to_start = minimum_action_points_to_start,
        .outcomes = { SafetyOutcome { successor, 0 } },
    };
}

void add_undirected_edge(SafetyProblem& problem, SafetyStateId first, SafetyStateId second, int cost = 1)
{
    problem.actions.emplace_back(
        deterministic_action("walk:" + std::to_string(first) + ":" + std::to_string(second), first, second, cost));
    problem.actions.emplace_back(
        deterministic_action("walk:" + std::to_string(second) + ":" + std::to_string(first), second, first, cost));
}

SafetyProblem make_problem(std::size_t state_count, SafetyStateId safe_exit)
{
    SafetyProblem problem;
    problem.states.reserve(state_count);
    for (SafetyStateId id = 0; id < state_count; ++id) {
        problem.states.emplace_back(
            SafetyState { .id = id, .safe_exit = id == safe_exit, .debug_name = "node-" + std::to_string(id) });
    }
    return problem;
}

int selected_action_requirement(const SafetyProblem& problem, const SafetySolution& solution, SafetyStateId state)
{
    const std::string* selected = solution.action(state);
    if (selected == nullptr) {
        return UnreachableActionPointRequirement;
    }
    const auto found = std::ranges::find(problem.actions, *selected, &SafetyAction::id);
    if (found == problem.actions.end()) {
        return UnreachableActionPointRequirement;
    }

    int requirement = std::max(found->minimum_action_points_to_start, found->action_point_cost);
    for (const SafetyOutcome& outcome : found->outcomes) {
        const int successor = solution.requirement(outcome.successor);
        if (successor >= UnreachableActionPointRequirement) {
            return UnreachableActionPointRequirement;
        }
        requirement = std::max(requirement, successor + found->action_point_cost - outcome.action_point_gain);
    }
    return requirement;
}

SafetyProblem make_random_problem(std::uint32_t seed)
{
    std::mt19937 random(seed);
    const std::size_t state_count = 5 + seed % 4;
    const std::uint32_t topology = seed % 4;
    SafetyProblem problem = make_problem(state_count, static_cast<SafetyStateId>(state_count - 1));

    std::vector<std::vector<bool>> adjacent(state_count, std::vector<bool>(state_count, false));
    const std::size_t split = state_count / 2;
    const auto component = [&](std::size_t node) {
        return topology == 2 && node >= split ? 1 : 0;
    };
    const auto connect = [&](std::size_t first, std::size_t second) {
        adjacent[first][second] = true;
        adjacent[second][first] = true;
    };

    if (topology == 1) {
        for (std::size_t node = 0; node < state_count; ++node) {
            connect(node, (node + 1) % state_count);
        }
    }
    else if (topology == 2) {
        for (std::size_t begin : { std::size_t { 0 }, split }) {
            const std::size_t end = begin == 0 ? split : state_count;
            for (std::size_t node = begin + 1; node < end; ++node) {
                connect(node - 1, node);
            }
            if (end - begin > 2) {
                connect(begin, end - 1);
            }
        }
    }
    else {
        for (std::size_t node = 1; node < state_count; ++node) {
            const std::size_t parent = std::uniform_int_distribution<std::size_t>(0, node - 1)(random);
            connect(node, parent);
        }
    }

    for (std::size_t first = 0; first < state_count; ++first) {
        for (std::size_t second = first + 1; second < state_count; ++second) {
            if (!adjacent[first][second] && component(first) == component(second) && random() % 100 < 35) {
                connect(first, second);
            }
        }
    }
    for (std::size_t first = 0; first < state_count; ++first) {
        for (std::size_t second = first + 1; second < state_count; ++second) {
            if (adjacent[first][second]) {
                add_undirected_edge(problem, static_cast<SafetyStateId>(first), static_cast<SafetyStateId>(second));
            }
        }
    }

    // Add AND actions whose result is chosen by the environment.  Deterministic
    // walk actions retain each component's connectivity; these actions exercise
    // worst-case outcome handling without bridging deliberately disconnected cases.
    if (state_count >= 4) {
        for (std::size_t source = 0; source + 1 < state_count; ++source) {
            std::vector<SafetyStateId> targets;
            std::vector<SafetyStateId> eligible;
            for (std::size_t target = 0; target < state_count; ++target) {
                if (target != source && component(target) == component(source)) {
                    eligible.emplace_back(static_cast<SafetyStateId>(target));
                }
            }
            std::ranges::shuffle(eligible, random);
            if (eligible.size() < 2) {
                continue;
            }
            targets.assign(eligible.begin(), eligible.begin() + 2);
            problem.actions.emplace_back(
                SafetyAction {
                    .id = "random:" + std::to_string(source),
                    .source = static_cast<SafetyStateId>(source),
                    .action_point_cost = 1,
                    .minimum_action_points_to_start = 1,
                    .outcomes = {
                        SafetyOutcome { targets[0], 0 },
                        SafetyOutcome { targets[1], 0 },
                    },
                });
        }
    }
    return problem;
}

void require_matches_oracle(const SafetyProblem& problem, int maximum_action_points)
{
    const BoundedOracleResult oracle = solve_with_bounded_and_or_oracle(problem, maximum_action_points);
    const SafetySolveResult solved = SafetyPlanner {}.solve(problem);
    REQUIRE(solved);

    for (const SafetyState& state : problem.states) {
        INFO("state=" << state.id);
        const int expected = oracle.required_action_points.at(state.id);
        const int actual = solved.solution->requirement(state.id);
        REQUIRE(actual == expected);
        for (int action_points = 0; action_points <= maximum_action_points; ++action_points) {
            REQUIRE(
                solved.solution->certifies(state.id, action_points) ==
                (expected < UnreachableActionPointRequirement && action_points >= expected));
        }
        if (!state.safe_exit && actual < UnreachableActionPointRequirement) {
            REQUIRE(solved.solution->action(state.id) != nullptr);
            REQUIRE(selected_action_requirement(problem, *solved.solution, state.id) == actual);
            REQUIRE(solved.solution->depth(state.id).has_value());
        }
    }
}

NodeId map_node_id(int row, int column, int floor = 1)
{
    const std::optional<NodeId> id = make_stable_node_id(floor, GridPosition { row, column });
    if (!id.has_value()) {
        throw std::invalid_argument("invalid test map position");
    }
    return *id;
}

Node make_map_node(int row, int column, NodeType type, int floor = 1)
{
    Node node;
    node.id = map_node_id(row, column, floor);
    node.floor = floor;
    node.position = { row, column };
    node.type = type;
    node.progress = NodeProgress::Active;
    node.traversal = default_traversal_for(type);
    node.identity_state = NodeIdentityState::Classified;
    node.identity_revealed = true;
    return node;
}

MapSnapshot make_diamond_map()
{
    MapSnapshot map;
    const NodeId start = map_node_id(0, 0);
    const NodeId upper = map_node_id(0, 1);
    const NodeId lower = map_node_id(1, 0);
    const NodeId exit = map_node_id(1, 1);
    REQUIRE(map.upsert_node(make_map_node(0, 0, NodeType::Empty)));
    REQUIRE(map.upsert_node(make_map_node(0, 1, NodeType::Incident)));
    REQUIRE(map.upsert_node(make_map_node(1, 0, NodeType::Rest)));
    REQUIRE(map.upsert_node(make_map_node(1, 1, NodeType::Final)));

    REQUIRE(map.upsert_edge(Edge { start, upper, EdgeKnowledge::Confirmed, {} }));
    REQUIRE(map.upsert_edge(Edge { start, lower, EdgeKnowledge::Confirmed, {} }));
    REQUIRE(map.upsert_edge(Edge { upper, exit, EdgeKnowledge::Confirmed, {} }));
    REQUIRE(map.upsert_edge(Edge { lower, exit, EdgeKnowledge::Confirmed, {} }));
    return map;
}

struct LiveNodeSpec
{
    GridPosition position;
    NodeType type = NodeType::Unknown;
    NodeIdentityState identity_state = NodeIdentityState::Classified;
    bool identity_revealed = true;
};

struct LiveEdgeSpec
{
    GridPosition first;
    GridPosition second;
};

// BF-P1-1 from dataset-collection-resume-20260811-6: floor 2, 19 vertices / 20 edges.
constexpr std::array<LiveNodeSpec, 19> LiveFloor2Nodes {
    LiveNodeSpec { { 0, 0 }, NodeType::Empty },
    LiveNodeSpec { { 0, 1 }, NodeType::Empty },
    LiveNodeSpec { { 0, 2 }, NodeType::Empty },
    LiveNodeSpec { { 0, 3 }, NodeType::Final },
    LiveNodeSpec { { 1, 0 }, NodeType::BattleNormal },
    LiveNodeSpec { { 1, 1 }, NodeType::Final },
    LiveNodeSpec { { 1, 2 }, NodeType::Empty },
    LiveNodeSpec { { 1, 3 }, NodeType::Incident },
    LiveNodeSpec { { 1, 4 }, NodeType::Empty },
    LiveNodeSpec { { 2, 0 }, NodeType::HideInvisible, NodeIdentityState::Hidden, false },
    LiveNodeSpec { { 2, 1 }, NodeType::Employ },
    LiveNodeSpec { { 2, 2 }, NodeType::Empty },
    LiveNodeSpec { { 2, 3 }, NodeType::Expedition },
    LiveNodeSpec { { 2, 4 }, NodeType::BattleNormal },
    LiveNodeSpec { { 3, 0 }, NodeType::Empty },
    LiveNodeSpec { { 3, 1 }, NodeType::ScrapShop },
    LiveNodeSpec { { 3, 2 }, NodeType::Empty },
    LiveNodeSpec { { 3, 3 }, NodeType::BattleNormal },
    LiveNodeSpec { { 3, 4 }, NodeType::Empty },
};

constexpr std::array<LiveEdgeSpec, 20> LiveFloor2Edges {
    LiveEdgeSpec { { 0, 0 }, { 0, 1 } }, LiveEdgeSpec { { 0, 0 }, { 1, 0 } }, LiveEdgeSpec { { 0, 1 }, { 0, 2 } },
    LiveEdgeSpec { { 0, 2 }, { 1, 2 } }, LiveEdgeSpec { { 0, 3 }, { 1, 3 } }, LiveEdgeSpec { { 1, 0 }, { 1, 1 } },
    LiveEdgeSpec { { 1, 1 }, { 1, 2 } }, LiveEdgeSpec { { 1, 2 }, { 2, 2 } }, LiveEdgeSpec { { 1, 3 }, { 2, 3 } },
    LiveEdgeSpec { { 1, 4 }, { 2, 4 } }, LiveEdgeSpec { { 2, 0 }, { 2, 1 } }, LiveEdgeSpec { { 2, 0 }, { 3, 0 } },
    LiveEdgeSpec { { 2, 1 }, { 2, 2 } }, LiveEdgeSpec { { 2, 2 }, { 2, 3 } }, LiveEdgeSpec { { 2, 2 }, { 3, 2 } },
    LiveEdgeSpec { { 2, 3 }, { 2, 4 } }, LiveEdgeSpec { { 2, 4 }, { 3, 4 } }, LiveEdgeSpec { { 3, 1 }, { 3, 2 } },
    LiveEdgeSpec { { 3, 2 }, { 3, 3 } }, LiveEdgeSpec { { 3, 3 }, { 3, 4 } },
};

MapSnapshot make_live_floor2_map(bool reverse_insertion)
{
    MapSnapshot map;
    std::vector<LiveNodeSpec> nodes(LiveFloor2Nodes.begin(), LiveFloor2Nodes.end());
    std::vector<LiveEdgeSpec> edges(LiveFloor2Edges.begin(), LiveFloor2Edges.end());
    if (reverse_insertion) {
        std::ranges::reverse(nodes);
        std::ranges::reverse(edges);
    }

    for (const LiveNodeSpec& spec : nodes) {
        Node node = make_map_node(spec.position.row, spec.position.column, spec.type, 2);
        node.identity_state = spec.identity_state;
        node.identity_revealed = spec.identity_revealed;
        REQUIRE(map.upsert_node(std::move(node)));
    }
    for (const LiveEdgeSpec& spec : edges) {
        REQUIRE(map.upsert_edge(
            Edge {
                map_node_id(spec.first.row, spec.first.column, 2),
                map_node_id(spec.second.row, spec.second.column, 2),
                EdgeKnowledge::Confirmed,
                {},
            }));
    }
    map.revision = 59;
    return map;
}

RunState make_live_floor2_run()
{
    RunState run;
    run.floor = 2;
    run.current_node = map_node_id(0, 1, 2);
    run.resources.action_points = 4;
    run.resources.movement_charges = {
        { MovementKind::M04, 1 },
        { MovementKind::M06, 2 },
        { MovementKind::M11, 3 },
    };
    run.active_movement = MovementKind::Walk;
    run.resources_revision = 2;
    for (const LiveNodeSpec& spec : LiveFloor2Nodes) {
        if (spec.identity_revealed) {
            run.revealed_nodes.emplace(map_node_id(spec.position.row, spec.position.column, 2));
        }
    }
    return run;
}

const OnDemandSafetyAction& require_action(const std::vector<OnDemandSafetyAction>* actions, std::string_view action_id)
{
    if (actions == nullptr) {
        throw std::runtime_error("state expansion returned no action vector");
    }
    const auto found = std::ranges::find_if(*actions, [&](const OnDemandSafetyAction& action) {
        return action.candidate.action_id == action_id;
    });
    if (found == actions->end()) {
        throw std::runtime_error("state expansion omitted expected action " + std::string(action_id));
    }
    return *found;
}

struct LiveReplayResult
{
    int initial_requirement = UnreachableActionPointRequirement;
    int first_action_requirement = UnreachableActionPointRequirement;
    int second_action_requirement = UnreachableActionPointRequirement;
    int final_action_points = 0;
    std::string first_action;
    std::string second_action;
};

LiveReplayResult replay_live_floor2_case(const MapSnapshot& map, bool use_compact_actions)
{
    constexpr NodeId CapturedCurrent = 562'949'953'421'314ULL;
    constexpr NodeId CapturedIncident = 562'949'986'975'750ULL;
    constexpr NodeId CapturedFinal = 562'949'953'421'318ULL;
    REQUIRE(map_node_id(0, 1, 2) == CapturedCurrent);
    REQUIRE(map_node_id(1, 3, 2) == CapturedIncident);
    REQUIRE(map_node_id(0, 3, 2) == CapturedFinal);
    REQUIRE(map.nodes().size() == 19);
    REQUIRE(map.edges().size() == 20);

    const RunState run = make_live_floor2_run();
    StateExpansionOptions options;
    options.use_compact_actions = use_compact_actions;
    options.maximum_states = 100000;
    options.strategy_goal_nodes = { CapturedFinal, map_node_id(1, 1, 2) };

    OnDemandStateGraph graph;
    std::string error;
    REQUIRE(graph.initialize(map, run, options, &error));
    REQUIRE(error.empty());

    const std::string first_action_id = "rogue_6_scrap_M_11:" + std::to_string(CapturedCurrent) + ":" +
                                        std::to_string(CapturedIncident) + ":" + std::to_string(CapturedIncident);
    const std::string second_action_id =
        "walk:" + std::to_string(CapturedIncident) + ":" + std::to_string(CapturedFinal);

    const SafetyStateId initial = graph.initial_state();
    const OnDemandSafetyAction& first = require_action(graph.actions(initial, &error), first_action_id);
    REQUIRE(error.empty());
    REQUIRE(first.candidate.movement == MovementKind::M11);
    REQUIRE(first.candidate.source == CapturedCurrent);
    REQUIRE(first.candidate.target == CapturedIncident);
    REQUIRE(first.candidate.path == std::vector<NodeId> { CapturedIncident });
    REQUIRE(first.outcomes.size() == 1);
    const MovementSpec* m11 = find_movement_spec(MovementKind::M11);
    REQUIRE(m11 != nullptr);
    REQUIRE(run.resources.movement_charges.at(MovementKind::M11) > 0);
    REQUIRE(node_type_allowed(*m11, map.find_node(CapturedIncident)->type));
    REQUIRE(is_in_geometric_range(map, CapturedCurrent, CapturedIncident, *m11));

    const SafetyStateId after_first_state = first.outcomes.front().successor;
    const OnDemandSafetyAction& second = require_action(graph.actions(after_first_state, &error), second_action_id);
    REQUIRE(error.empty());
    REQUIRE(second.candidate.movement == MovementKind::Walk);
    REQUIRE(second.candidate.path == std::vector<NodeId> { CapturedFinal });
    REQUIRE(map.edge_knowledge(CapturedIncident, CapturedFinal) == EdgeKnowledge::Confirmed);
    REQUIRE(second.outcomes.size() == 1);
    REQUIRE(graph.is_terminal(second.outcomes.front().successor));

    SafetyValueSolver solver(make_on_demand_safety_value_problem(graph, "live-floor2-19v20e"));
    LiveReplayResult result;
    result.initial_requirement = solver.N_bounded(initial, run.resources.action_points, &error);
    REQUIRE(error.empty());
    const int after_first_action_points = action_points_after(
        run.resources.action_points,
        first.action_point_cost,
        first.outcomes.front().action_point_gain);
    const int after_first_requirement = solver.N_bounded(after_first_state, after_first_action_points, &error);
    REQUIRE(error.empty());
    result.first_action_requirement = std::max(
        { first.minimum_action_points_to_start,
          first.action_point_cost,
          after_first_requirement + first.action_point_cost - first.outcomes.front().action_point_gain });
    const int after_second_action_points = action_points_after(
        after_first_action_points,
        second.action_point_cost,
        second.outcomes.front().action_point_gain);
    const int after_second_requirement =
        solver.N_bounded(second.outcomes.front().successor, after_second_action_points, &error);
    REQUIRE(error.empty());
    result.second_action_requirement = std::max(
        { second.minimum_action_points_to_start,
          second.action_point_cost,
          after_second_requirement + second.action_point_cost - second.outcomes.front().action_point_gain });
    REQUIRE(result.initial_requirement == 1);
    REQUIRE(result.first_action_requirement == 2);
    REQUIRE(result.second_action_requirement == 1);
    REQUIRE(run.resources.action_points >= result.first_action_requirement);
    REQUIRE(after_first_action_points >= result.second_action_requirement);
    result.final_action_points = after_second_action_points;
    REQUIRE(result.final_action_points == 2);
    result.first_action = first.candidate.action_id;
    result.second_action = second.candidate.action_id;
    return result;
}

MapSnapshot make_adjacent_boss_map()
{
    MapSnapshot map;
    const NodeId start = map_node_id(0, 0, 5);
    const NodeId boss = map_node_id(0, 1, 5);
    REQUIRE(map.upsert_node(make_map_node(0, 0, NodeType::Empty, 5)));
    REQUIRE(map.upsert_node(make_map_node(0, 1, NodeType::BattleBoss, 5)));
    REQUIRE(map.upsert_edge(Edge { start, boss, EdgeKnowledge::Confirmed, {} }));
    return map;
}

bool planner_state_less(const PlannerState& lhs, const PlannerState& rhs)
{
    return std::tie(
               lhs.node,
               lhs.movement_charges,
               lhs.completed_nodes,
               lhs.opened_blockers,
               lhs.consumed_lights,
               lhs.goal_progress_id,
               lhs.terminal) <
           std::tie(
               rhs.node,
               rhs.movement_charges,
               rhs.completed_nodes,
               rhs.opened_blockers,
               rhs.consumed_lights,
               rhs.goal_progress_id,
               rhs.terminal);
}

struct ExpandedOutcome
{
    SafetyStateId id = 0;
    PlannerState state;
    int action_point_gain = 0;
};

std::vector<ExpandedOutcome> expand_outcomes(const OnDemandStateGraph& graph, const OnDemandSafetyAction& action)
{
    std::vector<ExpandedOutcome> result;
    result.reserve(action.outcomes.size());
    for (const OnDemandSafetyOutcome& outcome : action.outcomes) {
        result.emplace_back(
            ExpandedOutcome { outcome.successor, graph.state(outcome.successor), outcome.action_point_gain });
    }
    std::ranges::sort(result, [](const ExpandedOutcome& lhs, const ExpandedOutcome& rhs) {
        if (planner_state_less(lhs.state, rhs.state)) {
            return true;
        }
        if (planner_state_less(rhs.state, lhs.state)) {
            return false;
        }
        return lhs.action_point_gain < rhs.action_point_gain;
    });
    return result;
}

void require_equivalent_state_graphs(const MapSnapshot& map, const RunState& run)
{
    StateExpansionOptions compact_options;
    compact_options.use_compact_actions = true;
    compact_options.maximum_states = 4096;

    StateExpansionOptions legacy_options = compact_options;
    legacy_options.use_compact_actions = false;

    OnDemandStateGraph compact;
    OnDemandStateGraph legacy;
    std::string error;
    REQUIRE(compact.initialize(map, run, compact_options, &error));
    REQUIRE(error.empty());
    REQUIRE(legacy.initialize(map, run, legacy_options, &error));
    REQUIRE(error.empty());

    std::deque<std::pair<SafetyStateId, SafetyStateId>> pending;
    std::set<std::pair<SafetyStateId, SafetyStateId>> visited;
    pending.emplace_back(compact.initial_state(), legacy.initial_state());

    while (!pending.empty()) {
        const auto [compact_id, legacy_id] = pending.front();
        pending.pop_front();
        if (!visited.emplace(compact_id, legacy_id).second) {
            continue;
        }
        REQUIRE(visited.size() <= compact_options.maximum_states);

        const PlannerState& compact_state = compact.state(compact_id);
        const PlannerState& legacy_state = legacy.state(legacy_id);
        INFO("compact_state=" << compact_id << " legacy_state=" << legacy_id << " node=" << compact_state.node);
        REQUIRE(compact_state == legacy_state);
        REQUIRE(compact.is_terminal(compact_id) == legacy.is_terminal(legacy_id));

        error.clear();
        const std::vector<OnDemandSafetyAction>* compact_actions = compact.actions(compact_id, &error);
        REQUIRE(compact_actions != nullptr);
        REQUIRE(error.empty());
        const std::vector<OnDemandSafetyAction>* legacy_actions = legacy.actions(legacy_id, &error);
        REQUIRE(legacy_actions != nullptr);
        REQUIRE(error.empty());
        REQUIRE(compact_actions->size() == legacy_actions->size());

        for (std::size_t action_index = 0; action_index < compact_actions->size(); ++action_index) {
            const OnDemandSafetyAction& compact_action = (*compact_actions)[action_index];
            const OnDemandSafetyAction& legacy_action = (*legacy_actions)[action_index];
            INFO(
                "action_index=" << action_index << " compact_action=" << compact_action.candidate.action_id
                                << " legacy_action=" << legacy_action.candidate.action_id);
            REQUIRE(compact_action.candidate.action_id == legacy_action.candidate.action_id);
            REQUIRE(compact_action.candidate.movement == legacy_action.candidate.movement);
            REQUIRE(compact_action.candidate.source == legacy_action.candidate.source);
            REQUIRE(compact_action.candidate.target == legacy_action.candidate.target);
            REQUIRE(compact_action.candidate.landing == legacy_action.candidate.landing);
            REQUIRE(compact_action.candidate.path == legacy_action.candidate.path);
            REQUIRE(compact_action.action_point_cost == legacy_action.action_point_cost);
            REQUIRE(compact_action.minimum_action_points_to_start == legacy_action.minimum_action_points_to_start);

            const std::vector<ExpandedOutcome> compact_outcomes = expand_outcomes(compact, compact_action);
            const std::vector<ExpandedOutcome> legacy_outcomes = expand_outcomes(legacy, legacy_action);
            REQUIRE(compact_outcomes.size() == legacy_outcomes.size());
            for (std::size_t outcome_index = 0; outcome_index < compact_outcomes.size(); ++outcome_index) {
                INFO("outcome_index=" << outcome_index);
                REQUIRE(compact_outcomes[outcome_index].state == legacy_outcomes[outcome_index].state);
                REQUIRE(
                    compact_outcomes[outcome_index].action_point_gain ==
                    legacy_outcomes[outcome_index].action_point_gain);
                pending.emplace_back(compact_outcomes[outcome_index].id, legacy_outcomes[outcome_index].id);
            }
        }
    }
}
} // namespace

TEST_CASE("BlackFlow safety threshold on a linear undirected map", "[blackflow][planner][oracle]")
{
    SafetyProblem problem = make_problem(3, 2);
    add_undirected_edge(problem, 0, 1, 2);
    add_undirected_edge(problem, 1, 2, 3);

    const SafetySolveResult solved = SafetyPlanner {}.solve(problem);
    REQUIRE(solved);
    REQUIRE(solved.solution->requirement(0) == 5);
    REQUIRE_FALSE(solved.solution->certifies(0, 4));
    REQUIRE(solved.solution->certifies(0, 5));
    REQUIRE(solved.solution->depth(0) == 2);
    require_matches_oracle(problem, 8);
}

TEST_CASE("BlackFlow equal-weight undirected cycle converges", "[blackflow][planner][oracle]")
{
    SafetyProblem problem = make_problem(6, 3);
    add_undirected_edge(problem, 0, 1);
    add_undirected_edge(problem, 1, 2);
    add_undirected_edge(problem, 2, 0);
    add_undirected_edge(problem, 2, 3);
    add_undirected_edge(problem, 4, 5); // An unrelated cycle component remains unreachable.

    const SafetySolveResult solved = SafetyPlanner {}.solve(problem);
    REQUIRE(solved);
    REQUIRE(solved.solution->requirement(0) == 2);
    REQUIRE(solved.solution->requirement(4) == UnreachableActionPointRequirement);
    REQUIRE(solved.solution->requirement(5) == UnreachableActionPointRequirement);
    require_matches_oracle(problem, 8);
}

TEST_CASE("BlackFlow disconnected start cannot reach an exit", "[blackflow][planner][oracle]")
{
    SafetyProblem problem = make_problem(4, 3);
    add_undirected_edge(problem, 0, 1);
    add_undirected_edge(problem, 2, 3);

    const SafetySolveResult solved = SafetyPlanner {}.solve(problem);
    REQUIRE(solved);
    REQUIRE(solved.solution->requirement(0) == UnreachableActionPointRequirement);
    REQUIRE(solved.solution->action(0) == nullptr);
    REQUIRE_FALSE(solved.solution->depth(0).has_value());
    require_matches_oracle(problem, 6);
}

TEST_CASE("BlackFlow diamond result is independent of insertion order", "[blackflow][planner][determinism]")
{
    SafetyProblem ordered = make_problem(4, 3);
    add_undirected_edge(ordered, 0, 1);
    add_undirected_edge(ordered, 0, 2);
    add_undirected_edge(ordered, 1, 3);
    add_undirected_edge(ordered, 2, 3);

    SafetyProblem reordered = ordered;
    reordered.states = { ordered.states[2], ordered.states[0], ordered.states[3], ordered.states[1] };
    std::ranges::reverse(reordered.actions);

    const SafetySolveResult first = SafetyPlanner {}.solve(ordered);
    const SafetySolveResult second = SafetyPlanner {}.solve(reordered);
    REQUIRE(first);
    REQUIRE(second);
    for (SafetyStateId state = 0; state < 4; ++state) {
        INFO("state=" << state);
        REQUIRE(first.solution->requirement(state) == second.solution->requirement(state));
        const std::string* first_action = first.solution->action(state);
        const std::string* second_action = second.solution->action(state);
        REQUIRE((first_action == nullptr) == (second_action == nullptr));
        if (first_action != nullptr) {
            INFO("first_action=" << *first_action << " second_action=" << *second_action);
            REQUIRE(*first_action == *second_action);
        }
    }
}

TEST_CASE(
    "BlackFlow 100 fixed-seed random undirected maps match bounded AND-OR oracle",
    "[blackflow][planner][oracle][property]")
{
    for (std::uint32_t index = 0; index < 100; ++index) {
        const std::uint32_t seed = 0x9e3779b9U * (index + 1U) ^ 0xa5a5a5a5U;
        INFO("seed=0x" << std::hex << seed);
        SafetyProblem problem = make_random_problem(seed);
        require_matches_oracle(problem, 16);

        SafetyProblem shuffled = problem;
        std::mt19937 random(seed ^ 0xa5a5a5a5U);
        std::ranges::shuffle(shuffled.states, random);
        std::ranges::shuffle(shuffled.actions, random);
        const SafetySolveResult ordered_solution = SafetyPlanner {}.solve(problem);
        const SafetySolveResult shuffled_solution = SafetyPlanner {}.solve(shuffled);
        REQUIRE(ordered_solution);
        REQUIRE(shuffled_solution);
        for (const SafetyState& state : problem.states) {
            REQUIRE(
                ordered_solution.solution->requirement(state.id) == shuffled_solution.solution->requirement(state.id));
            const std::string* ordered_action = ordered_solution.solution->action(state.id);
            const std::string* shuffled_action = shuffled_solution.solution->action(state.id);
            REQUIRE((ordered_action == nullptr) == (shuffled_action == nullptr));
            if (ordered_action != nullptr) {
                REQUIRE(*ordered_action == *shuffled_action);
            }
            REQUIRE(ordered_solution.solution->depth(state.id) == shuffled_solution.solution->depth(state.id));
        }
    }
}

TEST_CASE(
    "BlackFlow compact and legacy state expansion agree on a cyclic diamond",
    "[blackflow][planner][differential]")
{
    const MapSnapshot map = make_diamond_map();
    std::string error;
    REQUIRE(map.validate(&error));
    REQUIRE(error.empty());

    RunState run;
    run.floor = 1;
    run.current_node = map_node_id(0, 0);
    run.resources.action_points = 8;
    require_equivalent_state_graphs(map, run);
}

TEST_CASE(
    "BlackFlow replays the captured floor-2 19V/20E route safely and deterministically",
    "[blackflow][planner][live-replay]")
{
    const LiveReplayResult compact_forward = replay_live_floor2_case(make_live_floor2_map(false), true);
    const LiveReplayResult compact_reverse = replay_live_floor2_case(make_live_floor2_map(true), true);
    const LiveReplayResult legacy_forward = replay_live_floor2_case(make_live_floor2_map(false), false);
    const LiveReplayResult legacy_reverse = replay_live_floor2_case(make_live_floor2_map(true), false);

    for (const LiveReplayResult* replay : { &compact_reverse, &legacy_forward, &legacy_reverse }) {
        REQUIRE(replay->initial_requirement == compact_forward.initial_requirement);
        REQUIRE(replay->first_action_requirement == compact_forward.first_action_requirement);
        REQUIRE(replay->second_action_requirement == compact_forward.second_action_requirement);
        REQUIRE(replay->final_action_points == compact_forward.final_action_points);
        REQUIRE(replay->first_action == compact_forward.first_action);
        REQUIRE(replay->second_action == compact_forward.second_action);
    }
}

TEST_CASE(
    "BlackFlow keeps an adjacent boss processing move when it can trigger a bonus",
    "[blackflow][planner][processing][regression]")
{
    const MapSnapshot map = make_adjacent_boss_map();
    const NodeId start = map_node_id(0, 0, 5);
    const NodeId boss = map_node_id(0, 1, 5);
    const std::string expected =
        "rogue_6_scrap_M_11:" + std::to_string(start) + ":" + std::to_string(boss) + ":" + std::to_string(boss);

    for (int bonus_case = 0; bonus_case < 3; ++bonus_case) {
        for (const bool use_compact_actions : { false, true }) {
            INFO("bonus_case=" << bonus_case << " use_compact_actions=" << use_compact_actions);
            RunState run;
            run.floor = 5;
            run.current_node = start;
            run.resources.action_points = 3;
            run.resources.movement_charges.emplace(MovementKind::M11, 1);
            run.resources.white_model_birds = bonus_case == 0 ? 1 : 0;
            run.resources.painted_liberi = bonus_case == 1;

            StateExpansionOptions options;
            options.use_compact_actions = use_compact_actions;
            OnDemandStateGraph graph;
            std::string error;
            REQUIRE(graph.initialize(map, run, options, &error));
            REQUIRE(error.empty());
            const std::vector<OnDemandSafetyAction>* actions = graph.actions(graph.initial_state(), &error);
            REQUIRE(error.empty());
            REQUIRE(actions != nullptr);
            const auto found = std::ranges::find_if(*actions, [&](const OnDemandSafetyAction& action) {
                return action.candidate.action_id == expected;
            });
            if (bonus_case == 2) {
                REQUIRE(found == actions->end());
                continue;
            }
            REQUIRE(found != actions->end());
            const OnDemandSafetyAction& action = *found;
            REQUIRE(action.candidate.movement == MovementKind::M11);
            REQUIRE(action.candidate.target == boss);
            REQUIRE(action.action_point_cost == 1);
        }
    }
}
