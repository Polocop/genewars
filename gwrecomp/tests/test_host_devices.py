import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from host_devices import (  # noqa: E402
    AudioEventSink, DosClock, HostDevices, HostInput, IndexedVideo, MonotonicTimer, PIT8254,
)


class HostDeviceTests(unittest.TestCase):
    def test_pit_channel_zero_control_and_latched_count(self):
        pit = PIT8254()
        self.assertTrue(pit.write(0x43, 0x36))  # channel 0, low/high, mode 3
        self.assertTrue(pit.write(0x40, 0x34))
        self.assertTrue(pit.write(0x40, 0x12))
        self.assertEqual(pit.reload[0], 0x1234)
        self.assertTrue(pit.write(0x43, 0x00))  # latch channel 0 count
        self.assertEqual((pit.read(0x40), pit.read(0x40)), (0x34, 0x12))

    def test_pit_separate_channels_and_rejects_unsupported_width_and_port(self):
        pit = PIT8254()
        self.assertTrue(pit.write(0x43, 0x76))  # channel 1, low/high, mode 3
        pit.write(0x41, 0x78); pit.write(0x41, 0x56)
        self.assertEqual(pit.reload[1], 0x5678)
        self.assertEqual(pit.reload[0], 0)
        self.assertFalse(pit.write(0x43, 0x36, 2))
        self.assertFalse(pit.write(0x50, 0, 1))
        self.assertIsNone(pit.read(0x50))

    def test_pit_guest_cycles_decrement_and_wrap_reload_counter(self):
        pit=PIT8254()
        pit.write(0x43,0x36); pit.write(0x40,0x34); pit.write(0x40,0x12)
        pit.advance(1)
        self.assertEqual((pit.read(0x40),pit.read(0x40)),(0x33,0x12))
        pit.advance(0x1234-1)
        self.assertEqual((pit.read(0x40),pit.read(0x40)),(0x34,0x12))

    def test_pit_latch_is_stable_and_new_reload_resets_phase(self):
        pit=PIT8254()
        pit.write(0x43,0x36); pit.write(0x40,0x34); pit.write(0x40,0x12)
        pit.advance(10)
        pit.write(0x43,0x00)
        pit.advance(100)
        self.assertEqual((pit.read(0x40),pit.read(0x40)),(0x2a,0x12))
        pit.write(0x43,0x36); pit.write(0x40,0x78); pit.write(0x40,0x56)
        self.assertEqual((pit.read(0x40),pit.read(0x40)),(0x78,0x56))

    def test_pit_zero_divisor_is_65536_ticks(self):
        pit=PIT8254()
        pit.write(0x43,0x36); pit.write(0x40,0); pit.write(0x40,0)
        self.assertEqual(pit.reload[0],0x10000)
        pit.advance(1)
        self.assertEqual((pit.read(0x40),pit.read(0x40)),(0xff,0xff))
        pit.advance(0xffff)
        self.assertEqual((pit.read(0x40),pit.read(0x40)),(0,0))
    def test_timer_is_deterministic_with_fake_clock(self):
        now = [1_000_000_000]
        timer = MonotonicTimer(clock_ns=lambda: now[0], ticks_per_second=100)
        self.assertEqual(timer.ticks(), 0)
        now[0] += 250_000_000
        self.assertEqual(timer.ticks(), 25)
        self.assertEqual(timer.elapsed(10), 15)
        now[0] -= 500_000_000
        self.assertEqual(timer.ticks(), 25)  # monotonic clamp

    def test_dos_clock_is_deterministic_and_rolls_over_midnight(self):
        now=[0]
        clock=DosClock(clock_ns=lambda:now[0],start_time=(23,59,59,99))
        self.assertEqual(clock.time(),(23,59,59,99))
        now[0]+=10_000_000
        self.assertEqual(clock.time(),(0,0,0,0))
        now[0]-=20_000_000
        self.assertEqual(clock.time(),(0,0,0,0))
        with self.assertRaises(ValueError): DosClock(start_time=(24,0,0,0))
        virtual=DosClock(clock_ns=lambda:0,minimum_step_cs=5)
        self.assertEqual(virtual.time(),(0,0,0,5))
        self.assertEqual(virtual.time(),(0,0,0,10))

    def test_input_defaults_are_neutral_and_changes_are_explicit(self):
        inp = HostInput()
        self.assertEqual(inp.snapshot().keys_down, frozenset())
        self.assertEqual((inp.snapshot().mouse_x, inp.snapshot().mouse_y, inp.snapshot().mouse_buttons), (0, 0, 0))
        inp.key(42, True)
        inp.mouse(123, 45, 3)
        snap = inp.snapshot()
        self.assertIn(42, snap.keys_down)
        self.assertEqual((snap.mouse_x, snap.mouse_y, snap.mouse_buttons), (123, 45, 3))
        inp.key(42, False)
        self.assertNotIn(42, inp.snapshot().keys_down)

    def test_indexed_framebuffer_palette_blit_and_present_event(self):
        calls = []
        video = IndexedVideo(4, 3, lambda pixels, palette, w, h: calls.append((pixels, palette, w, h)))
        video.set_palette(1, [(255, 0, 0), (0, 255, 0)])
        video.write_pixels(1, 1, 2, 2, bytes([1, 2, 3, 4]))
        event = video.present()
        self.assertEqual(event.frame, 1)
        self.assertEqual((event.width, event.height), (4, 3))
        self.assertEqual(video.pixels[5:7], bytes([1, 2]))
        self.assertEqual(video.palette[1:3], [(255, 0, 0), (0, 255, 0)])
        self.assertEqual(calls[0][0], bytes(video.pixels))
        self.assertEqual(video.present().frame, 2)
        with self.assertRaises(ValueError):
            video.write_pixels(3, 2, 2, 1, b"12")
        with self.assertRaises(ValueError):
            video.set_palette(255, [(0, 0, 0), (1, 1, 1)])

    def test_audio_sink_records_requests_without_claiming_playback(self):
        audio = AudioEventSink()
        self.assertEqual(audio.play(7, volume=128, pan=-10).operation, "play")
        self.assertEqual(audio.stop(7).operation, "stop")
        self.assertEqual(audio.set_master_volume(200).volume, 200)
        self.assertEqual([x.sequence for x in audio.events], [1, 2, 3])
        with self.assertRaises(ValueError):
            audio.play(1, volume=256)

    def test_devices_aggregate_configurable_video(self):
        devices = HostDevices()
        video = devices.configure_video(2, 2)
        self.assertIs(devices.video, video)
        self.assertEqual(len(video.pixels), 4)


if __name__ == "__main__":
    unittest.main()
