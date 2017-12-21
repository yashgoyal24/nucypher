from nkms.crypto import api
from tests.utilities import EVENT_LOOP, MockNetworkyStuff


def test_bob_can_follow_treasure_map(enacted_policy, ursulas, alice, bob):
    """
    Upon receiving a TreasureMap, Bob populates his list of Ursulas with the correct number.
    """

    # Simulate Bob finding a TreasureMap on the DHT.
    # A test to show that Bob can do this can be found in test_network_actors.
    hrac, treasure_map = enacted_policy.hrac(), enacted_policy.treasure_map
    bob.treasure_maps[hrac] = treasure_map

    # Bob knows of no Ursulas.
    assert len(bob._ursulas) == 0

    # ...until he follows the TreasureMap.
    bob.follow_treasure_map(hrac)

    # Now he knows of all the Ursulas.
    assert len(bob._ursulas) == len(treasure_map)


def test_bob_can_issue_a_work_order_to_a_specific_ursula(enacted_policy, alice, bob, ursulas):
    """
    Now that Bob has his list of Ursulas, he can issue a WorkOrder to one.  Upon receiving the WorkOrder, Ursula
    saves it and responds by re-encrypting and giving Bob a cFrag.

    This is a multipart test; it shows proper relations between the Characters Ursula and Bob and also proper
    interchange between a KFrag, PFrag, and CFrag object in the context of REST-driven proxy re-encryption.
    """

    # We pick up our story with Bob already having followed the treasure map above, ie:
    hrac, treasure_map = enacted_policy.hrac(), enacted_policy.treasure_map
    bob.treasure_maps[hrac] = treasure_map
    bob.follow_treasure_map(hrac)
    assert len(bob._ursulas) == len(ursulas)

    the_pfrag = enacted_policy.pfrag
    the_hrac = enacted_policy.hrac()

    # Bob has no saved work orders yet, ever.
    assert len(bob._saved_work_orders) == 0

    # We'll test against just a single Ursula - here, we make a WorkOrder for just one.
    work_orders = bob.generate_work_orders(the_hrac, the_pfrag, num_ursulas=1)
    assert len(work_orders) == 1

    # Even though Bob generated the WorkOrder - and recorded the Ursula as such -
    # but he doesn't save it yet until he uses it for re-encryption.
    assert len(bob._saved_work_orders.ursulas) == 1
    assert len(bob._saved_work_orders) == 0

    networky_stuff = MockNetworkyStuff(ursulas)

    ursula_dht_key, work_order = list(work_orders.items())[0]

    # **** RE-ENCRYPTION HAPPENS HERE! ****
    cfrags = bob.get_reencrypted_c_frags(networky_stuff, work_order)
    the_cfrag = cfrags[0]  # We only gave one pFrag, so we only got one cFrag.

    # Having received the cFrag, Bob also saved the WorkOrder as complete.
    assert len(bob._saved_work_orders) == 1

    # OK, so cool - Bob has his cFrag!  Let's make sure everything went properly.  First, we'll show that it is in fact
    # the correct cFrag (ie, that Ursula performed reencryption properly).
    ursula = networky_stuff.get_ursula_by_id(work_order.ursula_id)
    the_kfrag = ursula.keystore.get_kfrag(work_order.kfrag_hrac)
    the_correct_cfrag = api.ecies_reencrypt(the_kfrag, the_pfrag.encrypted_key)
    assert the_cfrag == the_correct_cfrag  # It's the correct cfrag!

    # Now we'll show that Ursula saved the correct WorkOrder.
    work_orders_from_bob = ursula.work_orders(bob=bob)
    assert len(work_orders_from_bob) == 1
    assert work_orders_from_bob[0] == work_order


def test_bob_remember_that_he_has_cfrags_for_a_particular_pfrag(enacted_policy, alice, bob, ursulas):

    # In our last episode, Bob obtained a cFrag from Ursula.
    # Bob only has a saved WorkOrder from one Ursula.
    assert len(bob._saved_work_orders) == 1

    ursulas_by_pfrag = bob._saved_work_orders.by_pfrag(enacted_policy.pfrag)

    # ...and only one WorkOrder from that 1 Ursula.
    assert len(ursulas_by_pfrag.values()) == 1
    id_of_ursula_from_whom_we_already_have_a_cfrag = list(ursulas_by_pfrag.keys())[0]

    # The rest of this test will show that if Bob generates another WorkOrder, it's for a *different* Ursula.

    generated_work_order_map = bob.generate_work_orders(enacted_policy.hrac(), enacted_policy.pfrag, num_ursulas=1)
    id_of_this_new_ursula, new_work_order = list(generated_work_order_map.items())[0]

    # This new Ursula isn't the same one to whom we've already issued a WorkOrder.
    assert id_of_ursula_from_whom_we_already_have_a_cfrag != id_of_this_new_ursula

    # ...and, although this WorkOrder has the same pfrags as the saved one...
    assert new_work_order.pfrags[0] == enacted_policy.pfrag

    # ...it hasn't been saved yet (and won't be until do use it for re-encryption).
    assert new_work_order not in bob._saved_work_orders.by_pfrag(enacted_policy.pfrag).values()


def test_bob_gathers_and_combines(enacted_policy, alice, bob, ursulas):
    # Bob saved one work order last time.
    assert len(bob._saved_work_orders) == 1

    # ...but the policy requires us to collect more cfrags.
    assert len(bob._saved_work_orders) < enacted_policy.m

    # We'll just generate more without specifying how many.
    new_work_orders = bob.generate_work_orders(enacted_policy.hrac(), enacted_policy.pfrag)

    # Turns out that Bob is smart enough to only generate as many as he needs to have a work order for every kFrag.
    assert len(bob._saved_work_orders) + len(new_work_orders) == enacted_policy.n

    # TODO: Maybe show here that we can optionally just generate enough to get to m.  See #150

    # OK, now Bob gets re-encryption from the rest of the Ursulas in the TreasureMap.
    networky_stuff = MockNetworkyStuff(ursulas)
    for work_order in new_work_orders.values():
        bob.get_reencrypted_c_frags(networky_stuff, work_order)

    bob.combine_cfrags(enacted_policy.pfrag)
    assert False