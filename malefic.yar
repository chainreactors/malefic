rule DetectIoM_Malefic {
    meta:
        description = "Detect the IoM malefic implant"
        author = "Chainreactors team"
        date = "2025-07-05"

    strings:
        $iom = "this is 1n73rn4l 0f m4l1c3" ascii

    condition:
        $iom
}